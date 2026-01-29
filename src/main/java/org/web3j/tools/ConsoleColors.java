package org.web3j.tools;

public final class ConsoleColors {
    public static final String ANSI_RESET = "\u001B[0m";
    public static final String ANSI_BLACK = "\u001B[30m";
    public static final String ANSI_RED = "\u001B[31m";
    public static final String ANSI_GREEN = "\u001B[32m";
    public static final String ANSI_YELLOW = "\u001B[33m";
    public static final String ANSI_BLUE = "\u001B[34m";
    public static final String ANSI_PURPLE = "\u001B[35m";
    public static final String ANSI_CYAN = "\u001B[36m";
    public static final String ANSI_WHITE = "\u001B[37m";

    private static final String[] ANSI_COLORS = new String[] {
            ANSI_RESET,
            ANSI_BLACK,
            ANSI_RED,
            ANSI_GREEN,
            ANSI_YELLOW,
            ANSI_BLUE,
            ANSI_PURPLE,
            ANSI_CYAN,
            ANSI_WHITE
    };

    public static final String RESET = "(CC-RESET)";
    public static final String BLACK = "(CC-BLACK)";
    public static final String RED = "(CC-RED)";
    public static final String GREEN = "(CC-GREEN)";
    public static final String YELLOW = "(CC-YELLOW)";
    public static final String BLUE = "(CC-BLUE)";
    public static final String PURPLE = "(CC-PURPLE)";
    public static final String CYAN = "(CC-CYAN)";
    public static final String WHITE = "(CC-WHITE)";

    private static final String[] CODES = new String[] {
            RESET,
            BLACK,
            RED,
            GREEN,
            YELLOW,
            BLUE,
            PURPLE,
            CYAN,
            WHITE
    };

    public static String colorize(String text) {
        for (int i = 0; i < ANSI_COLORS.length; i++) {
            text = text.replace(CODES[i], ANSI_COLORS[i]);
        }
        return text;
    }

    public static void println(String text) {
        System.out.println(colorize(text));
    }
}
