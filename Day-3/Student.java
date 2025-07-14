package com.example.SpringBoot_Intern.Models;

import lombok.NoArgsConstructor;


public class Student {
    private int id;

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getFirstname() {
        return firstname;
    }

    public void setFirstname(String firstname) {
        this.firstname = firstname;
    }

    public String getDomain() {
        return domain;
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }

    public Student() {
    }

    private String firstname;
    private String domain;

    public Student(int id, String firstname, String domain) {
        this.id = id;
        this.firstname = firstname;
        this.domain = domain;
    }
}
