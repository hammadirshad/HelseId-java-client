package com.example.utils;

public class MethodsUtils {

    public static String getStringOrNull(Object value) {
        return value != null ? value.toString() : null;
    }
}