package com.example.springbootfirst.controllers;



import com.example.springbootfirst.models.RegisterDetails;
import com.example.springbootfirst.models.Roles;
import com.example.springbootfirst.models.UserDetailsDto;
import com.example.springbootfirst.services.EmployeeService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/employee")
public class EmployeeController {

    @Autowired
    private EmployeeService employeeService;

    @PreAuthorize("hasAnyRole('ADMIN','USER')")
    @GetMapping("/")
    public String route(){
        return "Welcome to SpringBoot Security";
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/get")
    public List<RegisterDetails> getMethod(){

        return employeeService.getMethod();
    }

    //@PreAuthorize("hasRole('USER')")
    @GetMapping("/{empID}")
    public RegisterDetails getEmployeeById(@PathVariable int empID){

        return employeeService.getEmployeeById(empID);
    }
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/role/{roleName}")
    public List<RegisterDetails> getRoles(@PathVariable String roleName){
        return employeeService.getEmployeeByRoles(roleName);
    }

    @PreAuthorize("hasRole('ADMIN')")
    @PutMapping("/update/{empID}")
    public String updateEmployee(@PathVariable int empID,@RequestBody RegisterDetails registerDetails){
        return employeeService.updateEmployee(empID,registerDetails);
    }

    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping("/add")
    public String addnewEmployee(@RequestBody RegisterDetails registerDetails){
        return employeeService.addNewEmployee(registerDetails);
    }



    @PreAuthorize("hasRole('ADMIN')")
    @DeleteMapping("/del/{empID}")
    public String deleteEmployee(@PathVariable int empID){
        return employeeService.deleteEmployeeById(empID);
    }



}
