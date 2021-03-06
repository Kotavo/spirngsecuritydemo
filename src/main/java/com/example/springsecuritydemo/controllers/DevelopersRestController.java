package com.example.springsecuritydemo.controllers;

import com.example.springsecuritydemo.models.Developer;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@RestController
@RequestMapping("/api/developers")
public class DevelopersRestController {

    private final List<Developer> DEVELOPERS = Stream.of(
            new Developer(1L, "First", "Firstov"),
            new Developer(2L, "Second", "Secondov"),
            new Developer(3L, "Thrid", "Thridov")
    ).collect(Collectors.toList());


    @GetMapping
    @PreAuthorize("hasAuthority('developers:read')")
    public List<Developer> getAll() {
        return DEVELOPERS;
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAuthority('developers:read')")
    public Developer getById(@PathVariable Long id) {
        return DEVELOPERS.stream().filter(developer -> developer.getId().equals(id)).findFirst().orElse(null);
    }

    @PostMapping
    @PreAuthorize("hasAuthority('developers:write')")
    public Developer create(@RequestBody Developer developer) {
        DEVELOPERS.add(developer);
        return developer;
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasAuthority('developers:write')")
    public void deleteById(@PathVariable Long id) {
        DEVELOPERS.removeIf(developer -> developer.getId().equals(id));

    }

}
