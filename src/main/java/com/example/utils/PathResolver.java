package com.example.utils;

import org.springframework.core.io.ClassPathResource;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;

public class PathResolver {

    public static InputStream getInputStream(String path) throws IOException {
        try {
            return new ClassPathResource(path).getInputStream();
        } catch (IOException e) {
            return new FileInputStream(path);
        }
    }

    public static URI getURI(String path) {
        try {
            return new ClassPathResource(path).getURI();
        } catch (IOException e) {
            return new File(path).toURI();
        }
    }
}
