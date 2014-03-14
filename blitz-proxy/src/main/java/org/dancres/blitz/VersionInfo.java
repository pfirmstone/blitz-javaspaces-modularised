package org.dancres.blitz;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.dancres.blitz.stats.Stat;
import org.dancres.blitz.stats.StatGenerator;
import org.dancres.blitz.stats.StatsBoard;
import org.dancres.blitz.stats.VersionStat;

public class VersionInfo {
    private static final Logger theLogger = getLogger();

    private static Logger getLogger() {
        Logger myLogger = Logger.getLogger("org.dancres.blitz.VersionInfo");
        myLogger.setLevel(Level.INFO);

        return myLogger;
    }

    public static final String PRODUCT_NAME = "Blitz JavaSpaces (PureJavaEdition)";
    public static final String EMAIL_CONTACT = "info@sorcersoft.com";
    public static final String SUPPLIER_NAME = "SorcerSoft.com S.A.";
    public static final String VERSION;
    public static final String VERSION_JE;

    static {
        StatsBoard.get().add(new Generator());
        Properties props = new Properties();
        InputStream versions = null;
        try {
            versions = VersionInfo.class.getResourceAsStream("VersionInfo.properties");
            props.load(versions);
            VERSION=props.getProperty("blitz");
            VERSION_JE=props.getProperty("sleepycat");
        } catch (IOException e) {
            throw new ExceptionInInitializerError(e);
        } finally {
            if (versions != null)
                try {
                    versions.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
        }
    }

    private static class Generator implements StatGenerator {

        private long _id = StatGenerator.UNSET_ID;

        public long getId() {
            return _id;
        }

        public void setId(long anId) {
            _id = anId;
        }

        public Stat generate() {
            return new VersionStat(_id, versionString());
        }
    }

    private static String versionString() {
        return PRODUCT_NAME + ", " + EMAIL_CONTACT + ", " +
                SUPPLIER_NAME + ", " + VERSION + ", Db/Java ${sleepycat.version}";
    }

    public static void dump() {
        theLogger.log(Level.INFO, new VersionStat(versionString()).toString());
    }

    public static void main(String anArgs[]) {
        System.out.println(new VersionStat(versionString()).toString());
    }
}