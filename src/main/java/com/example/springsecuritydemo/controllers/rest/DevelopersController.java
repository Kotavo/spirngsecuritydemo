package com.example.springsecuritydemo.controllers.rest;

import com.example.springsecuritydemo.models.Developer;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@RestController
@RequestMapping("/api/developers")
public class DevelopersController {

    private final List<Developer> DEVELOPERS = Stream.of(
            new Developer(1L,"First", "Firstov"),
            new Developer(2L, "Second", "Secondov"),
            new Developer(3L,"Thrid", "Thridov")
    ).collect(Collectors.toList());


    @GetMapping
    public List<Developer> getAll() {
        return DEVELOPERS;
    }

    @GetMapping("/{id}")
    public Developer getById(@PathVariable Long id){
        return DEVELOPERS.stream().filter(developer -> developer.getId().equals(id)).findFirst().orElse(null);
    }


}
