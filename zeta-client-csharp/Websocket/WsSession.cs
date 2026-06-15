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
using ZetaSdk.Native;

namespace ZetaSdk.WebSocket;

public enum WsMessageType { Text, Binary, Close }

public sealed class WsMessage
{
    public WsMessageType Type       { get; }
    public string?       Text       { get; }
    public int           BinarySize { get; }

    private WsMessage(WsMessageType type, string? text, int binarySize)
    {
        Type       = type;
        Text       = text;
        BinarySize = binarySize;
    }

    internal static WsMessage FromNative(IntPtr ptr)
    {
        var n = Marshal.PtrToStructure<NativeWsMessage>(ptr);
        return (NativeWsMessageType)n.type switch
        {
            NativeWsMessageType.Text   => new WsMessage(WsMessageType.Text,
                                              n.textPtr != IntPtr.Zero
                                                  ? Marshal.PtrToStringAnsi(n.textPtr)
                                                  : null,
                                              0),
            NativeWsMessageType.Binary => new WsMessage(WsMessageType.Binary, null, n.binarySize),
            _                          => new WsMessage(WsMessageType.Close,  null, 0),
        };
    }
}

public sealed class WsSession
{
    private readonly IntPtr _ptr;

    internal WsSession(IntPtr ptr) => _ptr = ptr;

    public void SendBinary(byte[] frame)
    {
        var handle = GCHandle.Alloc(frame, GCHandleType.Pinned);
        try   { ZetaSdkNative.ZetaSdk_WSSession_sendBinary(_ptr, handle.AddrOfPinnedObject(), frame.Length); }
        finally { handle.Free(); }
    }

    public void SendText(string text)
    {
        using var mem = new NativeMem();
        var bytes = Encoding.UTF8.GetBytes(text);
        var p     = mem.Str(text);
        ZetaSdkNative.ZetaSdk_WSSession_sendText(_ptr, p, bytes.Length);
    }

    public WsMessage ReceiveNext()
    {
        var ptr = ZetaSdkNative.ZetaSdk_WSSession_receiveNext(_ptr);
        if (ptr == IntPtr.Zero)
            throw new InvalidOperationException("ZetaSdk_WSSession_receiveNext returned null.");

        var msg = WsMessage.FromNative(ptr);
        ZetaSdkNative.ZetaSdk_WSMessage_destroy(ptr);
        return msg;
    }

    public void Close() => ZetaSdkNative.ZetaSdk_WSSession_close(_ptr);

    public string StompConnect(string host)
    {
        SendBinary(StompFrames.Connect(host));
        var reply = ReceiveNext();
        if (reply.Type != WsMessageType.Text)
            throw new ZetaSdkException($"Expected STOMP CONNECTED frame, got {reply.Type}.");
        return reply.Text ?? "";
    }

    public void StompSubscribe(string subscriptionId, string contextPath, string destination)
        => SendBinary(StompFrames.Subscribe(subscriptionId, contextPath, destination));

    public void StompSend(string contextPath, string destination, string bodyJson)
        => SendBinary(StompFrames.Send(contextPath, destination, bodyJson));

    public IReadOnlyList<string> ReceiveMessages(int count)
    {
        var results = new List<string>(count);
        for (int i = 0; i < count; i++)
        {
            var msg = ReceiveNext();
            switch (msg.Type)
            {
                case WsMessageType.Close:
                    return results;
                case WsMessageType.Text when msg.Text is not null:
                    results.Add(msg.Text);
                    break;
            }
        }
        return results;
    }
}

internal static class StompFrames
{
    public static byte[] Connect(string host)
        => Frame($"CONNECT\naccept-version:1.2\nhost:{host}\n\n");

    public static byte[] Subscribe(string id, string contextPath, string destination)
        => Frame($"SUBSCRIBE\nid:{id}\ndestination:{contextPath}{destination}\n\n");

    public static byte[] Send(string contextPath, string destination, string bodyJson)
        => Frame($"SEND\ndestination:{contextPath}{destination}\ncontent-type:application/json\n\n{bodyJson}");

    private static byte[] Frame(string content)
    {
        var utf8  = Encoding.UTF8.GetBytes(content);
        var frame = new byte[utf8.Length + 1];
        utf8.CopyTo(frame, 0);
        frame[^1] = 0x00;
        return frame;
    }
}
