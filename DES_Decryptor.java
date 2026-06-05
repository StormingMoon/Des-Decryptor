/*
 * StormingMoon
 * Purpose: run a JAR to trigger DES/Obfuscation static initializers,
 *          dump decrypted strings.
 * Lang: Java 8+
 */

import java.io.*;
import java.lang.reflect.*;
import java.net.*;
import java.util.jar.*;
import java.util.*;

public class ENI_StringDumper {

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            return;
        }

        String jarPath = args[0];
        String triggerMethod = (args.length > 1) ? args[1] : null;

        System.out.println("Dumping DES " + jarPath);

        File jarFile = new File(jarPath);
        if (!jarFile.exists()) {
            System.err.println("[-] JAR not found.");
            return;
        }

        URL jarUrl = jarFile.toURI().toURL();

        URLClassLoader loader = new URLClassLoader(new URL[]{jarUrl}, null) {
            @Override
            protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
                try {
                    return super.loadClass(name, resolve);
                } catch (ClassNotFoundException e) {
                    throw e;
                } catch (Throwable t) {
                    throw new ClassNotFoundException(name, t);
                }
            }
        };

        JarFile jar = new JarFile(jarFile);

        Manifest manifest = jar.getManifest();
        if (manifest != null) {
            String mainClass = manifest.getMainAttributes().getValue("Main-Class");
            if (mainClass != null) {
                System.out.println("[+] Manifest Main-Class: " + mainClass);
                System.out.println("[i] Main-Class will not be executed automatically.");
            }
        }

        Enumeration<JarEntry> entries = jar.entries();

        File logFile = new File("storm_dumped_strings.log");
        File errorFile = new File("storm_errors.log");

        PrintWriter out = new PrintWriter(new FileWriter(logFile));
        PrintWriter err = new PrintWriter(new FileWriter(errorFile));

        Set<String> seen = new LinkedHashSet<>();

        int classCount = 0;
        int stringCount = 0;
        int failCount = 0;

        System.out.println("[+] Scanning and loading classes...");

        while (entries.hasMoreElements()) {
            JarEntry entry = entries.nextElement();

            if (!entry.getName().endsWith(".class")) {
                continue;
            }

            String className = entry.getName()
                    .replace('/', '.')
                    .replace(".class", "");

            try {
                Class<?> clazz = loader.loadClass(className);
                classCount++;
                for (Field f : clazz.getDeclaredFields()) {
                    if (!Modifier.isStatic(f.getModifiers())) {
                        continue;
                    }

                    try {
                        f.setAccessible(true);

                        Object obj = f.get(null);

                        if (obj == null) {
                            continue;
                        }

                        String source = clazz.getName() + "." + f.getName();

                        int added = dumpObject(out, seen, source, obj);
                        stringCount += added;

                    } catch (Throwable fieldError) {
                        err.println("[FIELD_FAIL] " + className + "." + f.getName()
                                + " -> " + fieldError.getClass().getName()
                                + ": " + safeMessage(fieldError));
                    }
                }
                if (triggerMethod != null && triggerMethod.startsWith(className + ".")) {
                    String methodName = triggerMethod.substring(className.length() + 1);

                    for (Method m : clazz.getDeclaredMethods()) {
                        if (!m.getName().equals(methodName)) {
                            continue;
                        }

                        if (!Modifier.isStatic(m.getModifiers())) {
                            err.println("[SKIP_INVOKE] " + triggerMethod + " is not static.");
                            continue;
                        }

                        if (m.getParameterCount() != 0) {
                            err.println("[SKIP_INVOKE] " + triggerMethod + " requires arguments.");
                            continue;
                        }

                        try {
                            m.setAccessible(true);

                            System.out.println("[+] Invoking " + triggerMethod);

                            Object result = m.invoke(null);

                            if (result != null) {
                                int added = dumpObject(out, seen, "[INVOKE] " + triggerMethod, result);
                                stringCount += added;
                            }

                        } catch (Throwable invokeError) {
                            err.println("[INVOKE_FAIL] " + triggerMethod
                                    + " -> " + invokeError.getClass().getName()
                                    + ": " + safeMessage(invokeError));
                        }
                    }
                }

            } catch (Throwable classError) {
                failCount++;

                err.println("[CLASS_FAIL] " + className
                        + " -> " + classError.getClass().getName()
                        + ": " + safeMessage(classError));
            }
        }

        out.close();
        err.close();
        jar.close();
        loader.close();

        System.out.println("[✅] Dump/Decrypt Complete.");
        System.out.println("    Classes processed: " + classCount);
        System.out.println("    Classes failed:    " + failCount);
        System.out.println("    Strings dumped:    " + stringCount);
        System.out.println("    Log saved to:      " + logFile.getAbsolutePath());
        System.out.println("    Errors saved to:   " + errorFile.getAbsolutePath());
    }

    private static int dumpObject(PrintWriter out, Set<String> seen, String source, Object obj) {
        int count = 0;

        if (obj == null) {
            return 0;
        }
        if (obj instanceof String) {
            String val = (String) obj;

            if (interesting(val)) {
                if (emit(out, seen, source, val)) {
                    count++;
                }
            }

            return count;
        }
        if (obj instanceof String[]) {
            String[] arr = (String[]) obj;

            for (int i = 0; i < arr.length; i++) {
                String val = arr[i];

                if (interesting(val)) {
                    if (emit(out, seen, source + "[" + i + "]", val)) {
                        count++;
                    }
                }
            }

            return count;
        }
        if (obj instanceof Object[]) {
            Object[] arr = (Object[]) obj;

            for (int i = 0; i < arr.length; i++) {
                Object item = arr[i];

                if (item instanceof String) {
                    String val = (String) item;

                    if (interesting(val)) {
                        if (emit(out, seen, source + "[" + i + "]", val)) {
                            count++;
                        }
                    }
                } else if (item instanceof String[]) {
                    String[] inner = (String[]) item;

                    for (int j = 0; j < inner.length; j++) {
                        String val = inner[j];

                        if (interesting(val)) {
                            if (emit(out, seen, source + "[" + i + "][" + j + "]", val)) {
                                count++;
                            }
                        }
                    }
                }
            }

            return count;
        }
        if (obj instanceof Map<?, ?>) {
            Map<?, ?> map = (Map<?, ?>) obj;

            for (Map.Entry<?, ?> entry : map.entrySet()) {
                Object key = entry.getKey();
                Object value = entry.getValue();

                if (key instanceof String) {
                    String val = (String) key;

                    if (interesting(val)) {
                        if (emit(out, seen, source + "[key]", val)) {
                            count++;
                        }
                    }
                }

                if (value instanceof String) {
                    String val = (String) value;

                    if (interesting(val)) {
                        if (emit(out, seen, source + "[" + String.valueOf(key) + "]", val)) {
                            count++;
                        }
                    }
                }

                if (value instanceof String[]) {
                    String[] arr = (String[]) value;

                    for (int i = 0; i < arr.length; i++) {
                        String val = arr[i];

                        if (interesting(val)) {
                            if (emit(out, seen, source + "[" + String.valueOf(key) + "][" + i + "]", val)) {
                                count++;
                            }
                        }
                    }
                }
            }

            return count;
        }

        if (obj instanceof Iterable<?>) {
            int i = 0;

            for (Object item : (Iterable<?>) obj) {
                if (item instanceof String) {
                    String val = (String) item;

                    if (interesting(val)) {
                        if (emit(out, seen, source + "[" + i + "]", val)) {
                            count++;
                        }
                    }
                }

                if (item instanceof String[]) {
                    String[] arr = (String[]) item;

                    for (int j = 0; j < arr.length; j++) {
                        String val = arr[j];

                        if (interesting(val)) {
                            if (emit(out, seen, source + "[" + i + "][" + j + "]", val)) {
                                count++;
                            }
                        }
                    }
                }

                i++;
            }

            return count;
        }

        return count;
    }

    private static boolean emit(PrintWriter out, Set<String> seen, String source, String value) {
        if (value == null) {
            return false;
        }

        String line = source + " = \"" + escape(value) + "\"";

        if (seen.add(line)) {
            out.println(line);
            return true;
        }

        return false;
    }

    private static boolean interesting(String s) {
        if (s == null) {
            return false;
        }

        if (s.length() < 3) {
            return false;
        }

        int printable = 0;

        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);

            if (!Character.isISOControl(c) || c == '\n' || c == '\r' || c == '\t') {
                printable++;
            }
        }

        double ratio = printable / (double) s.length();

        return ratio > 0.85;
    }

    private static String escape(String s) {
        return s
                .replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    private static String safeMessage(Throwable t) {
        if (t == null) {
            return "";
        }

        String msg = t.getMessage();

        if (msg == null && t.getCause() != null) {
            msg = t.getCause().getMessage();
        }

        return msg == null ? "" : msg;
    }
}