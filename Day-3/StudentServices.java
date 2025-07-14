package com.example.SpringBoot_Intern.Services;

import com.example.SpringBoot_Intern.Models.Student;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.PathVariable;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Service
public class StudentServices {
    List<Student> st = new ArrayList<>(
            Arrays.asList(new Student(1, "kamalesh", "JAVA Developer"), new Student(2, "Yugesh", "VLSI"))
    );

    public List<Student> getMethod(){
        return st;
    }

    public Student getStudentByid(int id){
        int ind = 0;
        boolean flag = false;
        for(int i = 0;i < st.size();i++){
            if(id == st.get(i).getId()){
               ind = i;
               flag = true;
               break;
            }
        }
        if(flag){
            return st.get(ind);
        }
        else{
            return new Student();
        }
    }

    public String postMethod(Student stu) {
        st.add(stu);
        return "Student Added Successfully";
    }

    public String updateStudent(Student student) {
        int ind = 0;
        boolean flag = false;
        for(int i = 0;i < st.size();i++){
            if(student.getId() == st.get(i).getId()){
                ind = i;
                flag = true;
                break;
            }
        }
        if(flag){
            st.set(ind,student);
            return"Student Updated Successfully";
        }
        else{
            return "No such Student is There";
        }
    }

    public String deleteStudentByid(int id){
        int ind = 0;
        boolean flag = false;
        for(int i = 0;i < st.size();i++){
            if(id == st.get(i).getId()){
                ind = i;
                flag = true;
                break;
            }
        }
        if(flag){
            st.remove(ind);
            return"Deleted Student Successfully";
        }
        else{
            return "No such Student is There";
        }
    }


}
