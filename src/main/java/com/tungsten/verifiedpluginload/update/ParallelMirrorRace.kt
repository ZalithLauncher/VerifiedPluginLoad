package com.tungsten.verifiedpluginload.update

import java.io.IOException
import java.util.concurrent.Callable
import java.util.concurrent.ExecutionException
import java.util.concurrent.ExecutorCompletionService
import java.util.concurrent.Executors
import java.util.concurrent.Future

/** Runs every mirror concurrently and accepts the first candidate that passes the caller's checks. */
internal object ParallelMirrorRace {
    fun <Mirror, Candidate, Result> firstSuccessful(
        mirrors: List<Mirror>,
        download: (Mirror) -> Candidate,
        accept: (Candidate) -> Result
    ): Result {
        require(mirrors.isNotEmpty()) { "At least one mirror is required" }

        val executor = Executors.newFixedThreadPool(mirrors.size) { runnable ->
            Thread(runnable, "VerifiedPluginLoad-mirror").apply { isDaemon = true }
        }
        val completion = ExecutorCompletionService<Candidate>(executor)
        val futures = ArrayList<Future<Candidate>>(mirrors.size)
        val failures = ArrayList<Exception>()

        try {
            mirrors.forEach { mirror ->
                futures += completion.submit(Callable { download(mirror) })
            }

            var completed = 0
            while (completed < mirrors.size) {
                completed += 1
                val candidate = try {
                    completion.take().get()
                } catch (e: InterruptedException) {
                    Thread.currentThread().interrupt()
                    throw IOException("Interrupted while downloading the trust list", e)
                } catch (e: ExecutionException) {
                    when (val cause = e.cause) {
                        is Exception -> failures += cause
                        is Error -> throw cause
                        else -> failures += IOException("Trust-list mirror failed", cause)
                    }
                    continue
                }

                try {
                    return accept(candidate)
                } catch (e: Exception) {
                    failures += e
                }
            }

            throw MirrorRaceException(failures)
        } finally {
            futures.forEach { it.cancel(true) }
            executor.shutdownNow()
        }
    }
}

internal class MirrorRaceException(
    val failures: List<Exception>
) : IOException("No trust-list mirror produced an acceptable response") {
    init {
        failures.forEach(::addSuppressed)
    }
}
