package com.resolute.n4authentication.api;

import java.util.Map;
import java.util.StringTokenizer;
import java.util.TreeMap;

public class AuthMessage   {

    public static AuthMessage decodeFromString(String message)
    {
        AuthMessage auth = new AuthMessage();
        int space = message.indexOf(" ");
        if (space >= 0)
        {
            auth.setScheme(message.substring(0, space));
            String params = message.substring(space+1);
            StringTokenizer tokenizer = new StringTokenizer(params, ",");
            while (tokenizer.hasMoreElements())
            {
                String token = tokenizer.nextToken();
                int equal = token.indexOf("=");
                if (equal <= -1)
                {
                    throw new IllegalArgumentException("parameter missing '='");
                }
                String key = token.substring(0, equal).trim();
                String value = token.substring(equal + 1).trim();
                if (auth.getParameter(key) != null)
                {
                    throw new IllegalArgumentException("duplicate parameter");
                }
                auth.setParameter(key, value);
            }
        }
        else
        {
            auth.setScheme(message);
        }
        return auth;
    }

    public String encodeToString()
    {
        StringBuilder builder = new StringBuilder();
        builder.append(scheme);
        boolean firstEntry = true;
        for (Map.Entry<String, String> entry : params.entrySet())
        {
            if (firstEntry)
            {
                firstEntry = false;
                builder.append(" ");
            }
            else
            {
                builder.append(", ");
            }
            builder.append(entry.getKey());
            builder.append("=");
            builder.append(entry.getValue());
        }
        return builder.toString();
    }

    public void setScheme(String scheme)
    {
        this.scheme = scheme;
    }

    public String getScheme()
    {
        return scheme;
    }

    public void setParameter(String key, String value)
    {
        params.put(key, value);
    }

    public String getParameter(String key)
    {
        return params.get(key);
    }

    private String scheme;
    private Map<String, String> params = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
}