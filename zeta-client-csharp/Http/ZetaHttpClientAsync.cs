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

public sealed class ZetaHttpClientAsync : IDisposable
{
    private readonly IntPtr _ptr;
    private          bool   _disposed;

    internal ZetaHttpClientAsync(IntPtr ptr) => _ptr = ptr;

    public Task<ZetaHttpResponse> GetAsync(string relativeUrl,
        IReadOnlyDictionary<string, string>? headers = null,
        CancellationToken ct = default)
        => ExecuteAsync(relativeUrl, body: null, headers, ZetaSdkNative.ZetaHttpClient_getAsync, ct);

    public Task<ZetaHttpResponse> PostAsync(string relativeUrl, string? body = null,
        IReadOnlyDictionary<string, string>? headers = null,
        CancellationToken ct = default)
        => ExecuteAsync(relativeUrl, body, headers, ZetaSdkNative.ZetaHttpClient_postAsync, ct);

    public Task<ZetaHttpResponse> PutAsync(string relativeUrl, string? body = null,
        IReadOnlyDictionary<string, string>? headers = null,
        CancellationToken ct = default)
        => ExecuteAsync(relativeUrl, body, headers, ZetaSdkNative.ZetaHttpClient_putAsync, ct);

    public Task<ZetaHttpResponse> PatchAsync(string relativeUrl, string? body = null,
        IReadOnlyDictionary<string, string>? headers = null,
        CancellationToken ct = default)
        => ExecuteAsync(relativeUrl, body, headers, ZetaSdkNative.ZetaHttpClient_patchAsync, ct);

    public Task<ZetaHttpResponse> DeleteAsync(string relativeUrl,
        IReadOnlyDictionary<string, string>? headers = null,
        CancellationToken ct = default)
        => ExecuteAsync(relativeUrl, body: null, headers, ZetaSdkNative.ZetaHttpClient_deleteAsync, ct);

    public Task<ZetaHttpResponse> HeadAsync(string relativeUrl,
        IReadOnlyDictionary<string, string>? headers = null,
        CancellationToken ct = default)
        => ExecuteAsync(relativeUrl, body: null, headers, ZetaSdkNative.ZetaHttpClient_headAsync, ct);

    public Task<ZetaHttpResponse> OptionsAsync(string relativeUrl,
        IReadOnlyDictionary<string, string>? headers = null,
        CancellationToken ct = default)
        => ExecuteAsync(relativeUrl, body: null, headers, ZetaSdkNative.ZetaHttpClient_optionsAsync, ct);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void OnSuccessDelegate(int status, IntPtr body);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void OnErrorDelegate(IntPtr error);

    private delegate void NativeAsyncCall(
        IntPtr httpClient,
        ref NativeHttpRequest req,
        IntPtr onSuccess,
        IntPtr onError);

    private Task<ZetaHttpResponse> ExecuteAsync(
        string relativeUrl,
        string? body,
        IReadOnlyDictionary<string, string>? headers,
        NativeAsyncCall nativeCall,
        CancellationToken ct)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        var tcs = new TaskCompletionSource<ZetaHttpResponse>(
            TaskCreationOptions.RunContinuationsAsynchronously);

        ct.Register(() => tcs.TrySetCanceled(ct));

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

        OnSuccessDelegate onSuccess = (status, bodyPtr) =>
        {
            var bodyStr = bodyPtr != IntPtr.Zero
                ? Marshal.PtrToStringAnsi(bodyPtr) ?? ""
                : "";
            tcs.TrySetResult(new ZetaHttpResponse(status, bodyStr, new Dictionary<string, string>()));
        };

        OnErrorDelegate onError = errorPtr =>
        {
            var error = errorPtr != IntPtr.Zero
                ? Marshal.PtrToStringAnsi(errorPtr) ?? "unknown"
                : "unknown";
            tcs.TrySetException(new ZetaSdkException($"HTTP error: {error}"));
        };

        nativeCall(
            _ptr,
            ref req,
            Marshal.GetFunctionPointerForDelegate(onSuccess),
            Marshal.GetFunctionPointerForDelegate(onError));

        _ = tcs.Task.ContinueWith(_ =>
        {
            GC.KeepAlive(onSuccess);
            GC.KeepAlive(onError);
        });

        return tcs.Task;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        ZetaSdkNative.ZetaSdk_clearHttpClient(_ptr);
    }
}
