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

@file:OptIn(ExperimentalReactiveStateApi::class)

package de.gematik.zeta.client.ui.utils

import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.State
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelStoreOwner
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewModelScope
import androidx.lifecycle.viewmodel.compose.LocalViewModelStoreOwner
import androidx.lifecycle.viewmodel.compose.viewModel
import com.ensody.reactivestate.ContextualErrorsFlow
import com.ensody.reactivestate.ContextualStateFlowStore
import com.ensody.reactivestate.ContextualValRoot
import com.ensody.reactivestate.DI
import com.ensody.reactivestate.ExperimentalReactiveStateApi
import com.ensody.reactivestate.InMemoryStateFlowStore
import com.ensody.reactivestate.ReactiveStateContext
import com.ensody.reactivestate.ReactiveViewModel
import com.ensody.reactivestate.invokeOnCompletion
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.plus

@Composable
public inline fun <reified VM : ReactiveViewModel> reactiveViewModel(
    key: String? = null,
    crossinline onError: (Throwable) -> Unit,
    crossinline provider: ReactiveStateContext.() -> VM,
): State<VM> =
    onViewModel(key = key) {
        provider().also {
            it.onInit.trigger()
        }
    }.also { viewModel ->
        LaunchedEffect(viewModel.value) {
            ContextualErrorsFlow.get(viewModel.value.scope).collect { onError(it) }
        }
    }

@Composable
public inline fun <reified T> onViewModel(
    viewModelStoreOwner: ViewModelStoreOwner = checkNotNull(LocalViewModelStoreOwner.current) {
        "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"
    },
    key: String? = null,
    crossinline provider: ReactiveStateContext.() -> T,
): State<T> {
    val fullKey = "onViewModel:${T::class.simpleName}:$key"
    val storage = rememberSaveable<MutableMap<String, Any?>> { mutableMapOf() }
    return viewModel(viewModelStoreOwner = viewModelStoreOwner, key = fullKey) {
        WrapperViewModel { viewModelScope ->
            var scopeRef: CoroutineScope? = null
            viewModelScope.invokeOnCompletion { scopeRef?.cancel() }
            DI.derived {
                scopeRef = scope
                ReactiveStateContext(
                    scope + ContextualValRoot() + ContextualStateFlowStore.valued { InMemoryStateFlowStore(storage) },
                    this,
                ).provider()
            }
        }
    }.value.collectAsStateWithLifecycle()
}

public class WrapperViewModel<T>(provider: (CoroutineScope) -> StateFlow<T>) : ViewModel() {
    public val value: StateFlow<T> = provider(viewModelScope)
}
