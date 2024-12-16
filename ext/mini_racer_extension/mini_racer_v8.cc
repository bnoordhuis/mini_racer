#include "v8.h"
#include "v8-profiler.h"
#include "libplatform/libplatform.h"
#include "mini_racer_v8.h"
#include <memory>
#include <vector>
#include <cassert>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>

namespace {

// deliberately leaked on program exit,
// not safe to destroy after main() returns
v8::Platform *platform;
thread_local v8::Isolate *isolate;
thread_local v8::Local<v8::Context> context;
// extra context for when we need access to built-ins like Array
// and want to be sure they haven't been tampered with by JS code
thread_local v8::Local<v8::Context> safe_context;
thread_local Context *ruby_context;
thread_local int reason;
// safe because rooted in a HandleScope that persists for the thread's lifetime
thread_local v8::Local<v8::Object> webassembly_instance;
thread_local bool verbose_exceptions;

struct Serialized
{
    uint8_t *data = nullptr;
    size_t   size = 0;

    Serialized(v8::Isolate *isolate, v8::Local<v8::Value> v)
    {
        v8::ValueSerializer ser(isolate);
        ser.WriteHeader();
        if (!ser.WriteValue(context, v).FromMaybe(false)) return; // exception pending
        auto pair = ser.Release();
        data = pair.first;
        size = pair.second;
    }

    ~Serialized()
    {
        free(data);
    }
};

// throws JS exception on serialization error
bool reply(v8::Isolate *isolate, v8::Local<v8::Value> v)
{
    Serialized serialized(isolate, v);
    if (serialized.data)
        v8_reply(ruby_context, serialized.data, serialized.size);
    return serialized.data != nullptr; // exception pending if false
}

v8::Local<v8::Value> sanitize(v8::Local<v8::Value> v)
{
    // punch through proxies
    while (v->IsProxy()) v = v8::Proxy::Cast(*v)->GetTarget();
    // things that cannot be serialized
    if (v->IsArgumentsObject() ||
        v->IsPromise() ||
        v->IsModule() ||
        v->IsModuleNamespaceObject() ||
        v->IsWasmMemoryObject() ||
        v->IsWasmModuleObject() ||
        v->IsWasmNull()) {
        return v8::Object::New(isolate);
    }
    // V8's serializer doesn't accept symbols
    if (v->IsSymbol()) return v8::Symbol::Cast(*v)->Description(isolate);
    // TODO(bnoordhuis) replace this hack with something more principled
    if (v->IsFunction()) {
        auto type = v8::NewStringType::kNormal;
        const size_t size = sizeof(js_function_marker) / sizeof(*js_function_marker);
        return v8::String::NewFromTwoByte(isolate, js_function_marker, type, size).ToLocalChecked();
    }
    if (v->IsMapIterator() || v->IsSetIterator()) {
        bool is_key_value;
        v8::Local<v8::Array> array;
        if (v8::Object::Cast(*v)->PreviewEntries(&is_key_value).ToLocal(&array)) {
            return array;
        }
    }
    // WebAssembly.Instance objects are not serializable but there
    // is no direct way to detect them through the V8 C++ API
    if (v->IsObject() && v->InstanceOf(context, webassembly_instance).FromMaybe(false)) {
        return v8::Object::New(isolate);
    }
    return v;
}

v8::Local<v8::Value> to_error(v8::TryCatch *try_catch, int cause)
{
    v8::Local<v8::Value> t;
    char buf[1024];

    *buf = '\0';
    if (cause == NO_ERROR) {
        // nothing to do
    } else if (cause == PARSE_ERROR) {
        auto message = try_catch->Message();
        v8::String::Utf8Value s(isolate, message->Get());
        v8::String::Utf8Value name(isolate, message->GetScriptResourceName());
        if (!*s || !*name) goto fallback;
        auto line = message->GetLineNumber(context).FromMaybe(0);
        auto column = message->GetStartColumn(context).FromMaybe(0);
        snprintf(buf, sizeof(buf), "%c%s at %s:%d:%d", cause, *s, *name, line, column);
    } else if (try_catch->StackTrace(context).ToLocal(&t)) {
        v8::String::Utf8Value s(isolate, t);
        if (!*s) goto fallback;
        snprintf(buf, sizeof(buf), "%c%s", cause, *s);
    } else {
    fallback:
        v8::String::Utf8Value s(isolate, try_catch->Exception());
        const char *message = *s ? *s : "unexpected failure";
        if (cause == MEMORY_ERROR) message = "out of memory";
        if (cause == TERMINATED_ERROR) message = "terminated";
        snprintf(buf, sizeof(buf), "%c%s", cause, message);
    }
    v8::Local<v8::String> s;
    if (v8::String::NewFromUtf8(isolate, buf).ToLocal(&s)) return s;
    return v8::String::Empty(isolate);
}

extern "C" void v8_global_init(void)
{
    bool single_threaded = false;
    char *p; size_t n;
    v8_get_flags(&p, &n);
    if (p) {
        for (char *s = p; s < p+n; s += 1 + strlen(s)) {
            if (!strcmp(s, "--single_threaded") ||
                !strcmp(s, "--single-threaded")) {
                single_threaded = true;
            }
            v8::V8::SetFlagsFromString(s);
        }
        free(p);
    }
    v8::V8::InitializeICU();
    if (single_threaded) {
        platform = v8::platform::NewSingleThreadedDefaultPlatform().release();
    } else {
        platform = v8::platform::NewDefaultPlatform().release();
    }
    v8::V8::InitializePlatform(platform);
    v8::V8::Initialize();
}

void v8_gc_callback(v8::Isolate*, v8::GCType, v8::GCCallbackFlags, void *data)
{
    v8::HeapStatistics s;
    isolate->GetHeapStatistics(&s);
    int64_t used_heap_size = static_cast<int64_t>(s.used_heap_size());
    int64_t max_memory = *reinterpret_cast<int64_t*>(data);
    if (used_heap_size > max_memory) {
        reason = MEMORY_ERROR;
        isolate->TerminateExecution();
    }
}

extern "C" void v8_thread_init(Context *c, const uint8_t *snapshot_buf,
                               size_t snapshot_len, int64_t max_memory,
                               int verbose_exceptions_)
{
    verbose_exceptions = (verbose_exceptions_ != 0);
    ruby_context = c;
    std::unique_ptr<v8::ArrayBuffer::Allocator> allocator(
        v8::ArrayBuffer::Allocator::NewDefaultAllocator());
    v8::StartupData blob{nullptr, 0};
    v8::Isolate::CreateParams params;
    params.array_buffer_allocator = allocator.get();
    if (snapshot_len) {
        blob.data = reinterpret_cast<const char*>(snapshot_buf);
        blob.raw_size = snapshot_len;
        params.snapshot_blob = &blob;
    }
    isolate = v8::Isolate::New(params);
    if (max_memory > 0)
        isolate->AddGCEpilogueCallback(v8_gc_callback, &max_memory);
    {
        v8::Locker locker(isolate);
        v8::Isolate::Scope isolate_scope(isolate);
        v8::HandleScope handle_scope(isolate);
        context = v8::Context::New(isolate);
        safe_context = v8::Context::New(isolate);
        v8::Context::Scope context_scope(context);
        webassembly_instance = context
            ->Global()
            ->Get(context, v8::String::NewFromUtf8Literal(isolate, "WebAssembly"))
            .ToLocalChecked().As<v8::Object>()
            ->Get(context, v8::String::NewFromUtf8Literal(isolate, "Instance"))
            .ToLocalChecked().As<v8::Object>();
        v8_thread_main(ruby_context, reinterpret_cast<uintptr_t>(isolate));
    }
    isolate->Dispose();
}

void v8_api_callback(const v8::FunctionCallbackInfo<v8::Value>& info)
{
    v8::Local<v8::Array> request;
    {
        v8::Context::Scope context_scope(safe_context);
        request = v8::Array::New(isolate, 2);
    }
    for (int i = 0, n = info.Length(); i < n; i++) {
        request->Set(context, i, sanitize(info[i])).Check();
    }
    request->Set(context, info.Length(), info.Data()).Check(); // callback id
    {
        Serialized serialized(isolate, request);
        if (!serialized.data) return; // exception pending
        uint8_t marker = 'c'; // callback marker
        v8_reply(ruby_context, &marker, 1);
        v8_reply(ruby_context, serialized.data, serialized.size);
    }
    const uint8_t *p;
    size_t n;
    for (;;) {
        v8_roundtrip(ruby_context, &p, &n);
        if (*p == 'c') // callback reply
            break;
        if (*p == 'e') // ruby exception pending
            return isolate->TerminateExecution();
        v8_dispatch(ruby_context);
    }
    v8::ValueDeserializer des(isolate, p+1, n-1);
    des.ReadHeader(context).Check();
    v8::Local<v8::Value> result;
    if (!des.ReadValue(context).ToLocal(&result)) return; // exception pending
    v8::Local<v8::Object> response; // [result, err]
    if (!result->ToObject(context).ToLocal(&response)) return;
    v8::Local<v8::Value> err;
    if (!response->Get(context, 1).ToLocal(&err)) return;
    if (err->IsUndefined()) {
        if (!response->Get(context, 0).ToLocal(&result)) return;
        info.GetReturnValue().Set(result);
    } else {
        v8::Local<v8::String> message;
        if (!err->ToString(context).ToLocal(&message)) return;
        isolate->ThrowException(v8::Exception::Error(message));
    }
}

// response is err or empty string
extern "C" void v8_attach(const uint8_t *p, size_t n)
{
    v8::TryCatch try_catch(isolate);
    try_catch.SetVerbose(verbose_exceptions);
    v8::HandleScope handle_scope(isolate);
    v8::ValueDeserializer des(isolate, p, n);
    des.ReadHeader(context).Check();
    int cause = INTERNAL_ERROR;
    {
        v8::Local<v8::Value> request_v;
        if (!des.ReadValue(context).ToLocal(&request_v)) goto fail;
        v8::Local<v8::Object> request; // [name, id]
        if (!request_v->ToObject(context).ToLocal(&request)) goto fail;
        v8::Local<v8::Value> name_v;
        if (!request->Get(context, 0).ToLocal(&name_v)) goto fail;
        v8::Local<v8::Value> id_v;
        if (!request->Get(context, 1).ToLocal(&id_v)) goto fail;
        v8::Local<v8::String> name;
        if (!name_v->ToString(context).ToLocal(&name)) goto fail;
        v8::Local<v8::Int32> id;
        if (!id_v->ToInt32(context).ToLocal(&id)) goto fail;
        v8::Local<v8::Function> function;
        if (!v8::Function::New(context, v8_api_callback, id).ToLocal(&function)) goto fail;
        // support foo.bar.baz paths
        v8::String::Utf8Value path(isolate, name);
        if (!*path) goto fail;
        v8::Local<v8::Object> obj = context->Global();
        v8::Local<v8::String> key;
        for (const char *p = *path;;) {
            size_t n = strcspn(p, ".");
            auto type = v8::NewStringType::kNormal;
            if (!v8::String::NewFromUtf8(isolate, p, type, n).ToLocal(&key)) goto fail;
            if (p[n] == '\0') break;
            p += n + 1;
            v8::Local<v8::Value> val;
            if (!obj->Get(context, key).ToLocal(&val)) goto fail;
            if (!val->IsObject() && !val->IsFunction()) {
                val = v8::Object::New(isolate);
                if (!obj->Set(context, key, val).FromMaybe(false)) goto fail;
            }
            obj = val.As<v8::Object>();
        }
        if (!obj->Set(context, key, function).FromMaybe(false)) goto fail;
    }
    cause = NO_ERROR;
fail:
    if (!cause && try_catch.HasCaught()) cause = RUNTIME_ERROR;
    auto err = to_error(&try_catch, cause);
    if (!reply(isolate, err)) abort();
}

// response is errback [result, err] array
extern "C" void v8_call(const uint8_t *p, size_t n)
{
    v8::TryCatch try_catch(isolate);
    try_catch.SetVerbose(verbose_exceptions);
    v8::HandleScope handle_scope(isolate);
    v8::ValueDeserializer des(isolate, p, n);
    std::vector<v8::Local<v8::Value>> args;
    des.ReadHeader(context).Check();
    v8::Local<v8::Array> response;
    {
        v8::Context::Scope context_scope(safe_context);
        response = v8::Array::New(isolate, 2);
    }
    v8::Local<v8::Value> result;
    int cause = INTERNAL_ERROR;
    {
        v8::Local<v8::Value> request_v;
        if (!des.ReadValue(context).ToLocal(&request_v)) goto fail;
        v8::Local<v8::Object> request;
        if (!request_v->ToObject(context).ToLocal(&request)) goto fail;
        v8::Local<v8::Value> name_v;
        if (!request->Get(context, 0).ToLocal(&name_v)) goto fail;
        v8::Local<v8::String> name;
        if (!name_v->ToString(context).ToLocal(&name)) goto fail;
        cause = RUNTIME_ERROR;
        // support foo.bar.baz paths
        v8::String::Utf8Value path(isolate, name);
        if (!*path) goto fail;
        v8::Local<v8::Object> obj = context->Global();
        v8::Local<v8::String> key;
        for (const char *p = *path;;) {
            size_t n = strcspn(p, ".");
            auto type = v8::NewStringType::kNormal;
            if (!v8::String::NewFromUtf8(isolate, p, type, n).ToLocal(&key)) goto fail;
            if (p[n] == '\0') break;
            p += n + 1;
            v8::Local<v8::Value> val;
            if (!obj->Get(context, key).ToLocal(&val)) goto fail;
            if (!val->ToObject(context).ToLocal(&obj)) goto fail;
        }
        v8::Local<v8::Value> function_v;
        if (!obj->Get(context, key).ToLocal(&function_v)) goto fail;
        if (!function_v->IsFunction()) {
            // XXX it's technically possible for |function_v| to be a callable
            // object but those are effectively extinct; regexp objects used
            // to be callable but not anymore
            auto message = v8::String::NewFromUtf8Literal(isolate, "not a function");
            auto exception = v8::Exception::TypeError(message);
            isolate->ThrowException(exception);
            goto fail;
        }
        auto function = v8::Function::Cast(*function_v);
        assert(request->IsArray());
        int n = v8::Array::Cast(*request)->Length();
        for (int i = 1; i < n; i++) {
            v8::Local<v8::Value> val;
            if (!request->Get(context, i).ToLocal(&val)) goto fail;
            args.push_back(val);
        }
        auto maybe_result_v = function->Call(context, obj, args.size(), args.data());
        v8::Local<v8::Value> result_v;
        if (!maybe_result_v.ToLocal(&result_v)) goto fail;
        result = sanitize(result_v);
    }
    cause = NO_ERROR;
fail:
    if (isolate->IsExecutionTerminating()) {
        isolate->CancelTerminateExecution();
        cause = reason ? reason : TERMINATED_ERROR;
        reason = NO_ERROR;
    }
    if (!cause && try_catch.HasCaught()) cause = RUNTIME_ERROR;
    if (cause) result = v8::Undefined(isolate);
    auto err = to_error(&try_catch, cause);
    response->Set(context, 0, result).Check();
    response->Set(context, 1, err).Check();
    if (!reply(isolate, response)) {
        assert(try_catch.HasCaught());
        goto fail; // retry; can be termination exception
    }
}

// response is errback [result, err] array
extern "C" void v8_eval(const uint8_t *p, size_t n)
{
    v8::TryCatch try_catch(isolate);
    try_catch.SetVerbose(verbose_exceptions);
    v8::HandleScope handle_scope(isolate);
    v8::ValueDeserializer des(isolate, p, n);
    des.ReadHeader(context).Check();
    v8::Local<v8::Array> response;
    {
        v8::Context::Scope context_scope(safe_context);
        response = v8::Array::New(isolate, 2);
    }
    v8::Local<v8::Value> result;
    int cause = INTERNAL_ERROR;
    {
        v8::Local<v8::Value> request_v;
        if (!des.ReadValue(context).ToLocal(&request_v)) goto fail;
        v8::Local<v8::Object> request; // [filename, source]
        if (!request_v->ToObject(context).ToLocal(&request)) goto fail;
        v8::Local<v8::Value> filename;
        if (!request->Get(context, 0).ToLocal(&filename)) goto fail;
        v8::Local<v8::Value> source_v;
        if (!request->Get(context, 1).ToLocal(&source_v)) goto fail;
        v8::Local<v8::String> source;
        if (!source_v->ToString(context).ToLocal(&source)) goto fail;
        v8::ScriptOrigin origin(filename);
        v8::Local<v8::Script> script;
        cause = PARSE_ERROR;
        if (!v8::Script::Compile(context, source, &origin).ToLocal(&script)) goto fail;
        v8::Local<v8::Value> result_v;
        cause = RUNTIME_ERROR;
        auto maybe_result_v = script->Run(context);
        if (!maybe_result_v.ToLocal(&result_v)) goto fail;
        result = sanitize(result_v);
    }
    cause = NO_ERROR;
fail:
    if (isolate->IsExecutionTerminating()) {
        isolate->CancelTerminateExecution();
        cause = reason ? reason : TERMINATED_ERROR;
        reason = NO_ERROR;
    }
    if (!cause && try_catch.HasCaught()) cause = RUNTIME_ERROR;
    if (cause) result = v8::Undefined(isolate);
    auto err = to_error(&try_catch, cause);
    response->Set(context, 0, result).Check();
    response->Set(context, 1, err).Check();
    if (!reply(isolate, response)) {
        assert(try_catch.HasCaught());
        goto fail; // retry; can be termination exception
    }
}

extern "C" void v8_heap_stats(void)
{
    v8::HandleScope handle_scope(isolate);
    v8::HeapStatistics s;
    isolate->GetHeapStatistics(&s);
    v8::Local<v8::Object> response = v8::Object::New(isolate);
#define PROP(name)                                                  \
    do {                                                            \
        auto key = v8::String::NewFromUtf8Literal(isolate, #name);  \
        auto val = v8::Number::New(isolate, s.name());              \
        response->Set(context, key, val).Check();                   \
    } while (0)
    PROP(total_heap_size);
    PROP(total_heap_size);
    PROP(total_heap_size_executable);
    PROP(total_physical_size);
    PROP(total_available_size);
    PROP(total_global_handles_size);
    PROP(used_global_handles_size);
    PROP(used_heap_size);
    PROP(heap_size_limit);
    PROP(malloced_memory);
    PROP(external_memory);
    PROP(peak_malloced_memory);
    PROP(number_of_native_contexts);
    PROP(number_of_detached_contexts);
#undef PROP
    if (!reply(isolate, response)) abort();
}

struct OutputStream : public v8::OutputStream
{
    std::vector<uint8_t> buf;

    void EndOfStream() final {}
    int GetChunkSize() final { return 65536; }

    WriteResult WriteAsciiChunk(char* data, int size)
    {
        const uint8_t *p = reinterpret_cast<uint8_t*>(data);
        buf.insert(buf.end(), p, p+size);
        return WriteResult::kContinue;
    }
};

extern "C" void v8_heap_snapshot(void)
{
    v8::HandleScope handle_scope(isolate);
    auto snapshot = isolate->GetHeapProfiler()->TakeHeapSnapshot();
    OutputStream os;
    snapshot->Serialize(&os, v8::HeapSnapshot::kJSON);
    v8_reply(ruby_context, os.buf.data(), os.buf.size()); // not serialized because big
}

extern "C" void v8_pump_message_loop(void)
{
    v8::TryCatch try_catch(isolate);
    try_catch.SetVerbose(verbose_exceptions);
    v8::HandleScope handle_scope(isolate);
    bool ran_task = v8::platform::PumpMessageLoop(platform, isolate);
    if (isolate->IsExecutionTerminating()) goto fail;
    if (try_catch.HasCaught()) goto fail;
    if (ran_task) v8::MicrotasksScope::PerformCheckpoint(isolate);
    if (isolate->IsExecutionTerminating()) goto fail;
    if (platform->IdleTasksEnabled(isolate)) {
        double idle_time_in_seconds = 1.0 / 50;
        v8::platform::RunIdleTasks(platform, isolate, idle_time_in_seconds);
        if (isolate->IsExecutionTerminating()) goto fail;
        if (try_catch.HasCaught()) goto fail;
    }
fail:
    if (isolate->IsExecutionTerminating()) {
        isolate->CancelTerminateExecution();
        reason = NO_ERROR;
    }
    auto result = v8::Boolean::New(isolate, ran_task);
    if (!reply(isolate, result)) abort();
}

int snapshot(int is_warmup, const v8::String::Utf8Value& code,
             v8::StartupData blob, v8::StartupData *result,
             char (*errbuf)[512])
{
    // SnapshotCreator takes ownership of isolate
    v8::Isolate *isolate = v8::Isolate::Allocate();
    v8::StartupData *existing_blob = is_warmup ? &blob : nullptr;
    v8::SnapshotCreator snapshot_creator(isolate, nullptr, existing_blob);
    v8::Isolate::Scope isolate_scope(isolate);
    v8::HandleScope handle_scope(isolate);
    v8::TryCatch try_catch(isolate);
    try_catch.SetVerbose(verbose_exceptions);
    auto filename = is_warmup
        ? v8::String::NewFromUtf8Literal(isolate, "<warmup>")
        : v8::String::NewFromUtf8Literal(isolate, "<snapshot>");
    auto mode = is_warmup
        ? v8::SnapshotCreator::FunctionCodeHandling::kKeep
        : v8::SnapshotCreator::FunctionCodeHandling::kClear;
    int cause = INTERNAL_ERROR;
    {
        auto context = v8::Context::New(isolate);
        v8::Context::Scope context_scope(context);
        v8::Local<v8::String> source;
        auto type = v8::NewStringType::kNormal;
        if (!v8::String::NewFromUtf8(isolate, *code, type, code.length()).ToLocal(&source)) {
            v8::String::Utf8Value s(isolate, try_catch.Exception());
            if (*s) snprintf(*errbuf, sizeof(*errbuf), "%c%s", cause, *s);
            goto fail;
        }
        v8::ScriptOrigin origin(filename);
        v8::Local<v8::Script> script;
        cause = PARSE_ERROR;
        if (!v8::Script::Compile(context, source, &origin).ToLocal(&script)) {
            goto err;
        }
        cause = RUNTIME_ERROR;
        if (script->Run(context).IsEmpty()) {
        err:
            auto m = try_catch.Message();
            v8::String::Utf8Value s(isolate, m->Get());
            v8::String::Utf8Value name(isolate, m->GetScriptResourceName());
            auto line = m->GetLineNumber(context).FromMaybe(0);
            auto column = m->GetStartColumn(context).FromMaybe(0);
            snprintf(*errbuf, sizeof(*errbuf), "%c%s\n%s:%d:%d",
                     cause, *s, *name, line, column);
            goto fail;
        }
        cause = INTERNAL_ERROR;
        if (!is_warmup) snapshot_creator.SetDefaultContext(context);
    }
    if (is_warmup) {
        isolate->ContextDisposedNotification(false);
        auto context = v8::Context::New(isolate);
        snapshot_creator.SetDefaultContext(context);
    }
    *result = snapshot_creator.CreateBlob(mode);
    cause = NO_ERROR;
fail:
    return cause;
}

// response is errback [result, err] array
// note: currently needs --stress_snapshot in V8 debug builds
// to work around a buggy check in the snapshot deserializer
extern "C" void v8_snapshot(const uint8_t *p, size_t n)
{
    v8::TryCatch try_catch(isolate);
    try_catch.SetVerbose(verbose_exceptions);
    v8::HandleScope handle_scope(isolate);
    v8::ValueDeserializer des(isolate, p, n);
    des.ReadHeader(context).Check();
    v8::Local<v8::Array> response;
    {
        v8::Context::Scope context_scope(safe_context);
        response = v8::Array::New(isolate, 2);
    }
    v8::Local<v8::Value> result;
    v8::StartupData blob{nullptr, 0};
    int cause = INTERNAL_ERROR;
    char errbuf[512] = {0};
    {
        v8::Local<v8::Value> code_v;
        if (!des.ReadValue(context).ToLocal(&code_v)) goto fail;
        v8::String::Utf8Value code(isolate, code_v);
        if (!*code) goto fail;
        v8::StartupData init{nullptr, 0};
        cause = snapshot(/*is_warmup*/false, code, init, &blob, &errbuf);
        if (cause) goto fail;
    }
    if (blob.data) {
        auto data = reinterpret_cast<const uint8_t*>(blob.data);
        auto type = v8::NewStringType::kNormal;
        bool ok = v8::String::NewFromOneByte(isolate, data, type,
                                             blob.raw_size).ToLocal(&result);
        delete[] blob.data;
        blob = v8::StartupData{nullptr, 0};
        if (!ok) goto fail;
    }
    cause = NO_ERROR;
fail:
    if (isolate->IsExecutionTerminating()) {
        isolate->CancelTerminateExecution();
        cause = reason ? reason : TERMINATED_ERROR;
        reason = NO_ERROR;
    }
    if (!cause && try_catch.HasCaught()) cause = RUNTIME_ERROR;
    if (cause) result = v8::Undefined(isolate);
    v8::Local<v8::Value> err;
    if (*errbuf) {
        if (!v8::String::NewFromUtf8(isolate, errbuf).ToLocal(&err)) {
            err = v8::String::NewFromUtf8Literal(isolate, "unexpected error");
        }
    } else {
        err = to_error(&try_catch, cause);
    }
    response->Set(context, 0, result).Check();
    response->Set(context, 1, err).Check();
    if (!reply(isolate, response)) {
        assert(try_catch.HasCaught());
        goto fail; // retry; can be termination exception
    }
}

extern "C" void v8_warmup(const uint8_t *p, size_t n)
{
    v8::TryCatch try_catch(isolate);
    try_catch.SetVerbose(verbose_exceptions);
    v8::HandleScope handle_scope(isolate);
    std::vector<uint8_t> storage;
    v8::ValueDeserializer des(isolate, p, n);
    des.ReadHeader(context).Check();
    v8::Local<v8::Array> response;
    {
        v8::Context::Scope context_scope(safe_context);
        response = v8::Array::New(isolate, 2);
    }
    v8::Local<v8::Value> result;
    v8::StartupData blob{nullptr, 0};
    int cause = INTERNAL_ERROR;
    char errbuf[512] = {0};
    {
        v8::Local<v8::Value> request_v;
        if (!des.ReadValue(context).ToLocal(&request_v)) goto fail;
        v8::Local<v8::Object> request; // [snapshot, warmup_code]
        if (!request_v->ToObject(context).ToLocal(&request)) goto fail;
        v8::Local<v8::Value> blob_data_v;
        if (!request->Get(context, 0).ToLocal(&blob_data_v)) goto fail;
        v8::Local<v8::String> blob_data;
        if (!blob_data_v->ToString(context).ToLocal(&blob_data)) goto fail;
        assert(blob_data->IsOneByte());
        assert(blob_data->ContainsOnlyOneByte());
        if (const size_t len = blob_data->Length()) {
            auto flags = v8::String::NO_NULL_TERMINATION
                       | v8::String::PRESERVE_ONE_BYTE_NULL;
            storage.resize(len);
            blob_data->WriteOneByte(isolate, storage.data(), 0, len, flags);
        }
        v8::Local<v8::Value> code_v;
        if (!request->Get(context, 1).ToLocal(&code_v)) goto fail;
        v8::String::Utf8Value code(isolate, code_v);
        if (!*code) goto fail;
        auto data = reinterpret_cast<const char*>(storage.data());
        auto size = static_cast<int>(storage.size());
        v8::StartupData init{data, size};
        cause = snapshot(/*is_warmup*/true, code, init, &blob, &errbuf);
        if (cause) goto fail;
    }
    if (blob.data) {
        auto data = reinterpret_cast<const uint8_t*>(blob.data);
        auto type = v8::NewStringType::kNormal;
        bool ok = v8::String::NewFromOneByte(isolate, data, type,
                                             blob.raw_size).ToLocal(&result);
        delete[] blob.data;
        blob = v8::StartupData{nullptr, 0};
        if (!ok) goto fail;
    }
    cause = NO_ERROR;
fail:
    if (isolate->IsExecutionTerminating()) {
        isolate->CancelTerminateExecution();
        cause = reason ? reason : TERMINATED_ERROR;
        reason = NO_ERROR;
    }
    if (!cause && try_catch.HasCaught()) cause = RUNTIME_ERROR;
    if (cause) result = v8::Undefined(isolate);
    v8::Local<v8::Value> err;
    if (*errbuf) {
        if (!v8::String::NewFromUtf8(isolate, errbuf).ToLocal(&err)) {
            err = v8::String::NewFromUtf8Literal(isolate, "unexpected error");
        }
    } else {
        err = to_error(&try_catch, cause);
    }
    response->Set(context, 0, result).Check();
    response->Set(context, 1, err).Check();
    if (!reply(isolate, response)) {
        assert(try_catch.HasCaught());
        goto fail; // retry; can be termination exception
    }
}

extern "C" void v8_idle_notification(const uint8_t *p, size_t n)
{
    v8::TryCatch try_catch(isolate);
    v8::HandleScope handle_scope(isolate);
    v8::ValueDeserializer des(isolate, p, n);
    des.ReadHeader(context).Check();
    double idle_time_in_seconds = .01;
    {
        v8::Local<v8::Value> idle_time_in_seconds_v;
        if (!des.ReadValue(context).ToLocal(&idle_time_in_seconds_v)) goto fail;
        if (!idle_time_in_seconds_v->NumberValue(context).To(&idle_time_in_seconds)) goto fail;
    }
fail:
    double now = platform->MonotonicallyIncreasingTime();
    bool stop = isolate->IdleNotificationDeadline(now + idle_time_in_seconds);
    auto result = v8::Boolean::New(isolate, stop);
    if (!reply(isolate, result)) abort();
}

extern "C" void v8_low_memory_notification(void)
{
    isolate->LowMemoryNotification();
}

// called from ruby thread
extern "C" void v8_terminate_execution(uintptr_t isolate)
{
    reinterpret_cast<v8::Isolate*>(isolate)->TerminateExecution();
}

} // namespace anonymous
