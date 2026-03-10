package com.yushosei

import com.yushosei.cli.KakaoCli
import com.yushosei.cli.KakaoShell
import kotlin.system.exitProcess

fun main(args: Array<String>) {
    if (args.isEmpty()) {
        val exitCode = KakaoShell.run()
        if (exitCode != 0) {
            exitProcess(exitCode)
        }
        return
    }

    if (args.first().equals("shell", ignoreCase = true) || args.first().equals("cli", ignoreCase = true)) {
        val exitCode = KakaoShell.run()
        if (exitCode != 0) {
            exitProcess(exitCode)
        }
        return
    }

    if (
        args.first().equals("server", ignoreCase = true) ||
        args.first().equals("serve", ignoreCase = true)
    ) {
        val serverArgs = args.drop(1).toTypedArray()
        io.ktor.server.netty.EngineMain.main(serverArgs)
        return
    }

    val exitCode = KakaoCli.run(args.toList())
    if (exitCode != 0) {
        exitProcess(exitCode)
    }
}
