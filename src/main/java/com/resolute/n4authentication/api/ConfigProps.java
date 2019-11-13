package com.resolute.n4authentication.api;

import com.google.common.collect.ImmutableMap;
import com.resolute.n4authentication.impl.Endpoint;

import java.io.InputStream;
import java.util.Map;
import java.util.Properties;
import java.util.stream.Collectors;

public class ConfigProps extends IConfigFile {

    private ImmutableMap<String, String> configProps;

    public ConfigProps(String path){
        try{
            this.configProps = getProps(path);
        }catch(Exception catchall){
            catchall.printStackTrace();
        }
    }
    public static ConfigProps make(String conf){ return new ConfigProps(conf); }

    public ImmutableMap<String, String> getConfigProps(){ return configProps; }

    private final ImmutableMap<String, String> getProps(String conf) throws Exception{

        Map<String, String> map = null;

        try(InputStream input = Endpoint.class.getClassLoader().getResourceAsStream(conf)){
            Properties props = new Properties();
            if(input == null){
                throw new Exception("configuration file content is null or file wasn't found...!");
            }
            props.load(input);

            map = props.entrySet()
                    .stream()
                    .collect(
                            Collectors.toMap(e -> (String)e.getKey(),
                                    e-> (String)e.getValue()));
        } catch (Exception e) {
            e.printStackTrace();
        }

        if( map == null){
            throw new Exception("null map...!");
        }
        return ImmutableMap.copyOf(map);
    }
}
