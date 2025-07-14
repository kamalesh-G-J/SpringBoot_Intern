package com.example.SpringBoot_Intern.Controller;

import com.example.SpringBoot_Intern.Models.Student;
import com.example.SpringBoot_Intern.Services.StudentServices;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
public class StudentController {

    @Autowired
    private StudentServices hws;

    @GetMapping("/get")
    public List<Student> getMethod() {
        return hws.getMethod();
    }

    @GetMapping("/{id}")
    public Student getStudentByid(@PathVariable int id) {
        return hws.getStudentByid(id);
    }

    @PostMapping
    public String postmethod(@RequestBody Student student){
//        Student student = new Student(1,"Vijay","Actor");
        return hws.postMethod(student);
    }

    @PutMapping
    public String putmethod(@RequestBody Student student){
        return hws.updateStudent(student);
    }
  @DeleteMapping("/{id}")
    public String deletemethod(@PathVariable int id){
        return hws.deleteStudentByid(id);
  }


}
