package com.resolute.n4authentication.impl;

import com.resolute.n4authentication.api.ConfigProps;

public class N4Parameters extends ConfigProps {
    private N4Parameters(){
        super("n4params.conf");
    }

    public static N4Parameters make() { return new N4Parameters(); }
}
