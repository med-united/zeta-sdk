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
using System.Text;
using ZetaSdk.Config;
using ZetaSdk.Http;
using ZetaSdk.Native;
using ZetaSdk.WebSocket;

namespace ZetaSdk;

public sealed class ZetaClient : IDisposable
{
    private readonly IntPtr _ptr;
    private          bool   _disposed;
    private CustomSmcbHandle? _customSmcbHandle;
    private CustomStorageHandle? _customStorageHandle;
    private CustomLogHandle? _customLogHandle;

    private ZetaClient(IntPtr ptr) => _ptr = ptr;

    private ZetaClient(IntPtr ptr, CustomSmcbHandle? customSmcbHandle = null)
    {
        _ptr = ptr;
        _customSmcbHandle = customSmcbHandle;
    }

    public static ZetaClient Build(ZetaClientConfig config, bool disableTlsValidation = false)
    {
        ArgumentNullException.ThrowIfNull(config);
        var instance = new ZetaClient(IntPtr.Zero);

        using var mem       = new NativeMem();
        var       buildCfg  = instance.BuildNativeConfig(config, mem);
        var       ptr       = ZetaSdkNative.ZetaSdk_buildZetaClient(buildCfg, disableTlsValidation ? (byte)1 : (byte)0);

        if (ptr == IntPtr.Zero)
            throw new ZetaSdkException("ZetaSdk_buildZetaClient returned null. Check your configuration.");

        return new ZetaClient(ptr, instance._customSmcbHandle);
    }

    public ZetaHttpClient CreateHttpClient()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var ptr = ZetaSdkNative.ZetaSdk_buildHttpClient(_ptr);
        if (ptr == IntPtr.Zero)
            throw new ZetaSdkException("ZetaSdk_buildHttpClient returned null.");
        return new ZetaHttpClient(ptr);
    }

    public ZetaHttpClientAsync CreateHttpClientAsync()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var ptr = ZetaSdkNative.ZetaSdk_buildHttpClient(_ptr);
        if (ptr == IntPtr.Zero)
            throw new ZetaSdkException("Failed to create HTTP client.");
        return new ZetaHttpClientAsync(ptr);
    }

    public ZetaSdkStatus GetStatus()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        var result = ZetaSdkNative.ZetaSdk_status(_ptr);
        return result switch
        {
            0  => ZetaSdkStatus.NotRegistered,
            1  => ZetaSdkStatus.RegisteredNoValidTokens,
            2  => ZetaSdkStatus.HasRefreshToken,
            3  => ZetaSdkStatus.HasAccessAndRefreshToken,
            _  => ZetaSdkStatus.Unknown
        };
    }

    public void Logout()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        ZetaSdkNative.ZetaSdk_logout(_ptr);
    }

    public void OpenWebSocket(
        string url,
        IReadOnlyDictionary<string, string>? headers,
        Action<WsSession> handler)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(handler);
        using var mem = new NativeMem();

        WsSessionHandlerDelegate nativeDelegate = wsSessionPtr =>
            handler(new WsSession(wsSessionPtr));

        var handlerPtr = Marshal.GetFunctionPointerForDelegate(nativeDelegate);
        var urlPtr = mem.Str(url);
        var urlBytes = Encoding.UTF8.GetBytes(url);
        var (hdrPtr, hdrLen) = headers is { Count: > 0 }
            ? mem.HeaderArray(headers)
            : (IntPtr.Zero, 0);

        ZetaSdkNative.ZetaSdk_Client_ws(_ptr, urlPtr, urlBytes.Length, handlerPtr, hdrPtr, hdrLen);
        GC.KeepAlive(nativeDelegate);
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        ZetaSdkNative.ZetaSdk_clearZetaClient(_ptr);
    }

    private IntPtr BuildNativeConfig(ZetaClientConfig cfg, NativeMem mem)
    {
       var storageVTablePtr = IntPtr.Zero;
       if (cfg.Storage?.CustomStorage is { } customStorage)
       {
           _customStorageHandle = new CustomStorageHandle(customStorage);
           storageVTablePtr = _customStorageHandle.VTablePtr;
       }

       var logVTablePtr = IntPtr.Zero;
       if (cfg.Logger is { } logger)
       {
          _customLogHandle = new CustomLogHandle(logger, cfg.LogLevel);
          logVTablePtr = _customLogHandle.VTablePtr;
       }

       var storage = mem.Struct(new NativeStorageConfig
       {
           aesB64Key     = mem.Str(cfg.Storage?.AesB64Key),
           storagePath   = mem.Str(cfg.Storage?.StoragePath),
           customStorage = storageVTablePtr
       });

        var tpm     = mem.Struct(new NativeTpmConfig());

        var smbPtr = IntPtr.Zero;
        if (cfg.Auth.Smb is { } smb)
        {
            smbPtr = mem.Struct(new NativeSmbConfig
            {
                keystoreFile = mem.Str(smb.KeystoreFile),
                alias        = mem.Str(smb.Alias),
                password     = mem.Str(smb.Password)
            });
        }


        var (scopesPtr, scopesLen) = mem.StringArray(cfg.Auth.Scopes.ToArray());

        var smcbPtr = IntPtr.Zero;
        if (cfg.Auth.Smcb is { } smcb)
        {
            smcbPtr = mem.Struct(new NativeSmcbConfig
            {
                baseUrl        = mem.Str(smcb.BaseUrl),
                mandantId      = mem.Str(smcb.MandantId),
                clientSystemId = mem.Str(smcb.ClientSystemId),
                workspaceId    = mem.Str(smcb.WorkspaceId),
                userId         = mem.Str(smcb.UserId),
                cardHandle     = mem.Str(smcb.CardHandle),
                customSmcb     = IntPtr.Zero
            });
        }
        else if (cfg.Auth.CustomSmcb is { } customConnector)
        {
            _customSmcbHandle = new CustomSmcbHandle(customConnector);
            smcbPtr = mem.Struct(new NativeSmcbConfig
            {
                customSmcb = _customSmcbHandle.VTablePtr
            });
        }

        var auth = mem.Struct(new NativeAuthConfig
        {
            scopes               = scopesPtr,
            scopesCount          = scopesLen,
            exp                  = cfg.Auth.ExpirySeconds,
            aslProdEnvironment   = cfg.Auth.AslProdEnvironment,
            smbConfig            = smbPtr,
            smcbConfig           = smcbPtr,
            requiredOid          = mem.Str(cfg.Auth.RequiredRoleOid)
        });

        return mem.Struct(new NativeBuildConfig
        {
            resource       = mem.Str(cfg.Resource),
            productId      = mem.Str(cfg.ProductId),
            productVersion = mem.Str(cfg.ProductVersion),
            clientName     = mem.Str(cfg.ClientName),
            storageConfig  = storage,
            tpmConfig      = tpm,
            authConfig     = auth,
            logVTable      = logVTablePtr
        });
    }

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void WsSessionHandlerDelegate(IntPtr wsSession);
}
