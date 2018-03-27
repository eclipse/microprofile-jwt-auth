package config.seimpl.converters;

import org.eclipse.microprofile.config.spi.Converter;

public class StringArrayConverter implements Converter<String[]> {
    @Override
    public String[] convert(String value) {
        String[] array = value.split(",");
        return array;
    }
}
