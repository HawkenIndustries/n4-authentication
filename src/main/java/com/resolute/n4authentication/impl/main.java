package com.resolute.n4authentication.impl;

import com.resolute.n4authentication.api.ClientAuth;

public class main {
    public static void main(String[] args){

        //my client
        ClientAuth n4Client = ClientAuth.make();
        try{
            n4Client.setDebug(true);
            n4Client.login();
            n4Client.logout();
        }catch(Exception e){
            System.err.println("failed from Main's catch-all...!");
            e.printStackTrace();
        }
    }
}
