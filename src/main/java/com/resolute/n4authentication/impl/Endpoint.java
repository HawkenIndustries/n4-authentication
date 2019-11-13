package com.resolute.n4authentication.impl;

import com.resolute.n4authentication.api.ConfigProps;

public class Endpoint extends ConfigProps {
    private Endpoint(){
        super("endpoint.conf");
    }

    public static Endpoint make(){ return new Endpoint(); }
}
