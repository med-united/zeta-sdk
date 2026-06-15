/*
 * #%L
 * ZETA-Client
 * %%
 * (C) EY Strategy & Transactions GmbH, 2025, licensed for gematik GmbH
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * ******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
 * #L%
 */

using System.Runtime.InteropServices;
using ZetaSdk.Native;

namespace ZetaSdk.Http;

public sealed class ZetaHttpResponse
{
    public int                                Status    { get; }
    public string                             Body      { get; }
    public IReadOnlyDictionary<string,string> Headers   { get; }

    public bool IsSuccess     => Status is >= 200 and < 300;
    public bool IsClientError => Status is >= 400 and < 500;
    public bool IsServerError => Status is >= 500;

    internal ZetaHttpResponse(int status, string body, IReadOnlyDictionary<string,string> headers)
    {
        Status  = status;
        Body    = body;
        Headers = headers;
    }

    public override string ToString() => $"[{Status}] {Body}";
}

public sealed class ZetaHttpClient : IDisposable
{
    private readonly IntPtr    _ptr;
    private          bool      _disposed;

    internal ZetaHttpClient(IntPtr ptr) => _ptr = ptr;

    public ZetaHttpResponse Get(string relativeUrl,
        IReadOnlyDictionary<string, string>? headers = null)
        => Execute(relativeUrl, body: null, headers, ZetaSdkNative.ZetaHttpClient_get);

    public ZetaHttpResponse Post(string relativeUrl, string? body = null,
        IReadOnlyDictionary<string, string>? headers = null)
        => Execute(relativeUrl, body, headers, ZetaSdkNative.ZetaHttpClient_post);

    public ZetaHttpResponse Put(string relativeUrl, string? body = null,
        IReadOnlyDictionary<string, string>? headers = null)
        => Execute(relativeUrl, body, headers, ZetaSdkNative.ZetaHttpClient_put);

    public ZetaHttpResponse Patch(string relativeUrl, string? body = null,
        IReadOnlyDictionary<string, string>? headers = null)
        => Execute(relativeUrl, body, headers, ZetaSdkNative.ZetaHttpClient_patch);

    public ZetaHttpResponse Delete(string relativeUrl,
        IReadOnlyDictionary<string, string>? headers = null)
        => Execute(relativeUrl, body: null, headers, ZetaSdkNative.ZetaHttpClient_delete);

    public ZetaHttpResponse Head(string relativeUrl,
        IReadOnlyDictionary<string, string>? headers = null)
        => Execute(relativeUrl, body: null, headers, ZetaSdkNative.ZetaHttpClient_head);

    public ZetaHttpResponse Options(string relativeUrl,
        IReadOnlyDictionary<string, string>? headers = null)
        => Execute(relativeUrl, body: null, headers, ZetaSdkNative.ZetaHttpClient_options);

    private delegate IntPtr NativeCall(IntPtr httpClient, ref NativeHttpRequest req);

    private ZetaHttpResponse Execute(
        string relativeUrl, string? body,
        IReadOnlyDictionary<string, string>? headers,
        NativeCall nativeCall)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        using var mem = new NativeMem();
        var (hdrPtr, hdrLen) = headers is { Count: > 0 }
            ? mem.HeaderArray(headers)
            : (IntPtr.Zero, 0);

        var req = new NativeHttpRequest
        {
            url          = mem.Str(relativeUrl),
            body         = body is null ? IntPtr.Zero : mem.Str(body),
            headers      = hdrPtr,
            headersCount = hdrLen
        };

        return ReadAndDestroy(nativeCall(_ptr, ref req));
    }

    private static ZetaHttpResponse ReadAndDestroy(IntPtr respPtr)
    {
        if (respPtr == IntPtr.Zero)
            throw new ZetaSdkException("Native HTTP call returned null.");

        var native = Marshal.PtrToStructure<NativeHttpResponse>(respPtr);
        var error  = native.error != IntPtr.Zero ? Marshal.PtrToStringAnsi(native.error) : null;
        var body   = native.body  != IntPtr.Zero ? Marshal.PtrToStringAnsi(native.body) : "";

        var headers = new Dictionary<string, string>();
        if (native.headers != IntPtr.Zero && native.headersCount > 0)
        {
            var size = Marshal.SizeOf<NativeHttpHeader>();
            for (int i = 0; i < native.headersCount; i++)
            {
                var h = Marshal.PtrToStructure<NativeHttpHeader>(native.headers + i * size);
                var key   = h.key   != IntPtr.Zero ? Marshal.PtrToStringAnsi(h.key)   : null;
                var value = h.value != IntPtr.Zero ? Marshal.PtrToStringAnsi(h.value) : null;
                if (key is not null)
                    headers[key] = value ?? "";
            }
        }

        ZetaSdkNative.ZetaHttpResponse_destroy(respPtr);

        if (!string.IsNullOrEmpty(error))
            throw new ZetaSdkException($"HTTP error: {error}");

        return new ZetaHttpResponse(native.status, body ?? "", headers);
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        ZetaSdkNative.ZetaSdk_clearHttpClient(_ptr);
    }
}
