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

using System.Reflection;
using System.Runtime.InteropServices;

namespace ZetaSdk.Native;

public static class ZetaNativeLoader
{
    private static string? _path;
    private static bool    _registered;

    public static void SetLibraryPath(string absolutePath)
    {
        _path = absolutePath ?? throw new ArgumentNullException(nameof(absolutePath));
        EnsureRegistered();
    }

    private static void EnsureRegistered()
    {
        if (_registered) return;
        _registered = true;
        NativeLibrary.SetDllImportResolver(Assembly.GetExecutingAssembly(), Resolve);
    }

    private static IntPtr Resolve(string libraryName, Assembly assembly, DllImportSearchPath? searchPath)
    {
        if (libraryName != ZetaSdkNative.Lib) return IntPtr.Zero;

        if (_path is not null && NativeLibrary.TryLoad(_path, out var handle))
            return handle;

        return NativeLibrary.Load(libraryName, assembly, searchPath);
    }
}
