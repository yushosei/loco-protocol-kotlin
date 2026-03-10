package com.yushosei.cli

object KakaoShell {
    fun run(): Int {
        printBanner()
        val reader = System.`in`.bufferedReader()

        while (true) {
            print("kakao> ")
            System.out.flush()

            val line = reader.readLine() ?: return 0
            val trimmed = line.trim()
            if (trimmed.isEmpty()) {
                continue
            }

            when (trimmed.lowercase()) {
                "exit", "quit" -> {
                    println("종료합니다.")
                    return 0
                }

                "clear" -> {
                    repeat(40) { println() }
                    continue
                }
            }

            val tokensResult = runCatching { tokenize(trimmed) }
            if (tokensResult.isFailure) {
                System.err.println(tokensResult.exceptionOrNull()?.message ?: "failed to parse command")
                continue
            }
            val tokens = tokensResult.getOrThrow()
            if (tokens.isEmpty()) {
                continue
            }

            if (tokens.first().equals("server", ignoreCase = true) ||
                tokens.first().equals("serve", ignoreCase = true) ||
                tokens.first().equals("web", ignoreCase = true)
            ) {
                println("서버 모드는 별도 실행입니다. gradlew run --args=\"server\" 로 실행하세요.")
                continue
            }

            KakaoCli.run(tokens)
        }
    }

    private fun printBanner() {
        println("KakaoTalk Kotlin 셸")
        println("명령은 help, 전체 API는 api-list --verbose, 종료는 quit")
        println("기본 흐름: bootstrap -> rooms --limit 10 -> read <chatId> --limit 20 -> send <chatId> --message \"안녕하세요\"")
        println("웹과 REST 서버: gradlew run --args=\"server\"")
        println()
    }

    private fun tokenize(line: String): List<String> {
        val tokens = mutableListOf<String>()
        val current = StringBuilder()
        var quote: Char? = null
        var escaping = false

        line.forEach { ch ->
            when {
                escaping -> {
                    current.append(ch)
                    escaping = false
                }

                ch == '\\' -> escaping = true
                quote != null && ch == quote -> quote = null
                quote == null && (ch == '"' || ch == '\'') -> quote = ch
                quote == null && ch.isWhitespace() -> {
                    if (current.isNotEmpty()) {
                        tokens += current.toString()
                        current.setLength(0)
                    }
                }

                else -> current.append(ch)
            }
        }

        require(!escaping) { "명령 끝에 잘못된 escape 문자가 있습니다." }
        require(quote == null) { "닫히지 않은 따옴표가 있습니다." }

        if (current.isNotEmpty()) {
            tokens += current.toString()
        }
        return tokens
    }
}
