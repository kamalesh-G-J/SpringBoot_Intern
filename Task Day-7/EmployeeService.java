package com.example.springbootfirst.services;


import com.example.springbootfirst.models.RegisterDetails;
import com.example.springbootfirst.models.Roles;
import com.example.springbootfirst.repository.RegisterDetailRepository;
import com.example.springbootfirst.repository.RolesRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestBody;

import java.util.List;

@Service
public class EmployeeService {
    @Autowired
    PasswordEncoder passwordEncoder;

    @Autowired
    RegisterDetailRepository registerDetailRepository;

    @Autowired
    RolesRepository rolesRepository;

    public List<RegisterDetails> getMethod() {

        return registerDetailRepository.findAll();
    }

    public RegisterDetails getEmployeeById(int empID) {
        return registerDetailRepository.findById(empID).orElse(new RegisterDetails());
    }

    public List<RegisterDetails> getEmployeeByRoles(String roleName){
        Roles role = rolesRepository.findByRoleName(roleName)
                .orElseThrow(()->new RuntimeException("Role Not Found" + roleName));
        return registerDetailRepository.findByRoles(role);
    }

    public String addNewEmployee(RegisterDetails registerDetails){
        registerDetailRepository.save(registerDetails);
        return "Employee Added Successfully";
    }

    public String updateEmployee(int empID,RegisterDetails registerDetails) {
        RegisterDetails user = registerDetailRepository.findById(empID)
                        .orElseThrow(()-> new RuntimeException("No such user found"));
        user.setName(registerDetails.getName());
        user.setEmail(registerDetails.getEmail());
        user.setPassword(passwordEncoder.encode(registerDetails.getPassword()));
        user.setUserName(registerDetails.getUserName());
        user.setRoles(registerDetails.getRoles());

        registerDetailRepository.save(user);
        return "Employee Updated Successfully";
    }

    public String deleteEmployeeById(int empID){
        registerDetailRepository.deleteById(empID);
        return "Employee Deleted Successfully";
    }
}
