package com.example.SpringBoot_Intern.Repository;

import com.example.SpringBoot_Intern.Models.Student;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface StudentRepo extends JpaRepository<Student,Integer> {

    List<Student> findByDomain(String domain);
}
