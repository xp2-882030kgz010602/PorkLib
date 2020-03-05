/*
 * Adapted from The MIT License (MIT)
 *
 * Copyright (c) 2018-2020 DaPorkchop_
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software
 * is furnished to do so, subject to the following conditions:
 *
 * Any persons and/or organizations using this software must include the above copyright notice and this permission notice,
 * provide sufficient credit to the original authors of the project (IE: DaPorkchop_), as well as provide a link to the original project.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 */

package net.daporkchop.lib.concurrent.future;

import io.netty.util.concurrent.GenericFutureListener;
import lombok.Getter;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.experimental.Accessors;
import net.daporkchop.lib.concurrent.PFuture;

import java.util.concurrent.CompletionStage;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executor;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.BiConsumer;
import java.util.function.BiFunction;
import java.util.function.Consumer;
import java.util.function.Function;

/**
 * Wraps a Java {@link Future} into a {@link PFuture}.
 *
 * @author DaPorkchop_
 */
@RequiredArgsConstructor
@Getter
@Accessors(fluent = true)
public class JavaFutureWrapper<V> implements PFuture<V> {
    @NonNull
    protected final Future<V> delegate;

    @Override
    public boolean isSuccess() {
        return false;
    }

    @Override
    public boolean isCancellable() {
        return false;
    }

    @Override
    public Throwable cause() {
        return null;
    }

    @Override
    public PFuture<V> addListener(@NonNull GenericFutureListener<? extends io.netty.util.concurrent.Future<? super V>> listener) {
        return null;
    }

    @Override
    public PFuture<V> addListeners(@NonNull GenericFutureListener<? extends io.netty.util.concurrent.Future<? super V>>... listeners) {
        return null;
    }

    @Override
    public PFuture<V> removeListener(@NonNull GenericFutureListener<? extends io.netty.util.concurrent.Future<? super V>> listener) {
        return null;
    }

    @Override
    public PFuture<V> removeListeners(@NonNull GenericFutureListener<? extends io.netty.util.concurrent.Future<? super V>>... listeners) {
        return null;
    }

    @Override
    public PFuture<V> sync() throws InterruptedException {
        return null;
    }

    @Override
    public PFuture<V> syncUninterruptibly() {
        return null;
    }

    @Override
    public PFuture<V> await() throws InterruptedException {
        return null;
    }

    @Override
    public PFuture<V> awaitUninterruptibly() {
        return null;
    }

    @Override
    public boolean await(long timeout, TimeUnit unit) throws InterruptedException {
        return false;
    }

    @Override
    public boolean await(long timeoutMillis) throws InterruptedException {
        return false;
    }

    @Override
    public boolean awaitUninterruptibly(long timeout, TimeUnit unit) {
        return false;
    }

    @Override
    public boolean awaitUninterruptibly(long timeoutMillis) {
        return false;
    }

    @Override
    public V getNow() {
        return null;
    }

    @Override
    public <U> PFuture<U> thenApply(@NonNull Function<? super V, ? extends U> fn) {
        return null;
    }

    @Override
    public <U> PFuture<U> thenApplyAsync(@NonNull Function<? super V, ? extends U> fn, @NonNull Executor executor) {
        return null;
    }

    @Override
    public PFuture<Void> thenAccept(@NonNull Consumer<? super V> action) {
        return null;
    }

    @Override
    public PFuture<Void> thenAcceptAsync(@NonNull Consumer<? super V> action, @NonNull Executor executor) {
        return null;
    }

    @Override
    public PFuture<Void> thenRun(@NonNull Runnable action) {
        return null;
    }

    @Override
    public PFuture<Void> thenRunAsync(@NonNull Runnable action, @NonNull Executor executor) {
        return null;
    }

    @Override
    public <U, V1> CompletionStage<V1> thenCombine(@NonNull CompletionStage<? extends U> other, @NonNull BiFunction<? super V, ? super U, ? extends V1> fn) {
        return null;
    }

    @Override
    public <U, V1> CompletionStage<V1> thenCombineAsync(@NonNull CompletionStage<? extends U> other, @NonNull BiFunction<? super V, ? super U, ? extends V1> fn, @NonNull Executor executor) {
        return null;
    }

    @Override
    public <U> PFuture<Void> thenAcceptBoth(@NonNull CompletionStage<? extends U> other, @NonNull BiConsumer<? super V, ? super U> action) {
        return null;
    }

    @Override
    public <U> PFuture<Void> thenAcceptBothAsync(@NonNull CompletionStage<? extends U> other, @NonNull BiConsumer<? super V, ? super U> action, @NonNull Executor executor) {
        return null;
    }

    @Override
    public PFuture<Void> runAfterBoth(@NonNull CompletionStage<?> other, @NonNull Runnable action) {
        return null;
    }

    @Override
    public PFuture<Void> runAfterBothAsync(@NonNull CompletionStage<?> other, @NonNull Runnable action, @NonNull Executor executor) {
        return null;
    }

    @Override
    public <U> PFuture<U> applyToEither(@NonNull CompletionStage<? extends V> other, @NonNull Function<? super V, U> fn) {
        return null;
    }

    @Override
    public <U> PFuture<U> applyToEitherAsync(@NonNull CompletionStage<? extends V> other, @NonNull Function<? super V, U> fn, @NonNull Executor executor) {
        return null;
    }

    @Override
    public PFuture<Void> acceptEither(@NonNull CompletionStage<? extends V> other, @NonNull Consumer<? super V> action) {
        return null;
    }

    @Override
    public PFuture<Void> acceptEitherAsync(@NonNull CompletionStage<? extends V> other, @NonNull Consumer<? super V> action, @NonNull Executor executor) {
        return null;
    }

    @Override
    public PFuture<Void> runAfterEither(@NonNull CompletionStage<?> other, @NonNull Runnable action) {
        return null;
    }

    @Override
    public PFuture<Void> runAfterEitherAsync(@NonNull CompletionStage<?> other, @NonNull Runnable action, @NonNull Executor executor) {
        return null;
    }

    @Override
    public <U> PFuture<U> thenCompose(@NonNull Function<? super V, ? extends CompletionStage<U>> fn) {
        return null;
    }

    @Override
    public <U> PFuture<U> thenComposeAsync(@NonNull Function<? super V, ? extends CompletionStage<U>> fn, @NonNull Executor executor) {
        return null;
    }

    @Override
    public PFuture<V> exceptionally(@NonNull Function<Throwable, ? extends V> fn) {
        return null;
    }

    @Override
    public PFuture<V> whenComplete(@NonNull BiConsumer<? super V, ? super Throwable> action) {
        return null;
    }

    @Override
    public PFuture<V> whenCompleteAsync(@NonNull BiConsumer<? super V, ? super Throwable> action, @NonNull Executor executor) {
        return null;
    }

    @Override
    public <U> PFuture<U> handle(@NonNull BiFunction<? super V, Throwable, ? extends U> fn) {
        return null;
    }

    @Override
    public <U> PFuture<U> handleAsync(@NonNull BiFunction<? super V, Throwable, ? extends U> fn, @NonNull Executor executor) {
        return null;
    }

    @Override
    public boolean cancel(boolean mayInterruptIfRunning) {
        return false;
    }

    @Override
    public boolean isCancelled() {
        return false;
    }

    @Override
    public boolean isDone() {
        return false;
    }

    @Override
    public V get() throws InterruptedException, ExecutionException {
        return null;
    }

    @Override
    public V get(long timeout, TimeUnit unit) throws InterruptedException, ExecutionException, TimeoutException {
        return null;
    }
}