package com.swift.apidev.preval;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.servers.Server;

@OpenAPIDefinition( 
    servers = {
       @Server(url = "/", description = "Default Server URL")
    }
) 
@SpringBootApplication
public class Application {
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);

        String variable1= "Hello, World! This is a simple Java code.";
		System.out.println(variable1);

    }
}
