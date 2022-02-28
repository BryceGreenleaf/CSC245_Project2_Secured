import java.io.*;
import java.text.Normalizer;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CSC245_Project2 {
    private static final String WHITELISTED_PATH = "P:\\CSC245_Project2_Secured\\"; //Whitelist Path

    // This regex will match valid RFC 5322 email addresses.
    private static final Pattern emailValidatorPattern = Pattern.compile("^[a-zA-Z0-9_-]+(?:.[a-zA-Z0-9_-]+)*@[a-zA-Z0-9-]+(?:.[a-zA-Z0-9-]+)*$"); //ISD51-J

    public static String normalize(String input) {
        // Normalize string with compatibility decomposition + canonical composition.
        return Normalizer.normalize(input, Normalizer.Form.NFKC);
    }

    public static String validate(String description, String input) {
        // Normalize the input string.
        String canonical = normalize(input);

        // Validate the input string against the email matcher regex.
        if (!emailValidatorPattern.matcher(input).matches()) {
            throw new SecurityException(description + " failed validation.");
        }

        // If the email was validated, return the normalized string.
        return canonical;
    }


    public static void main(String[] args) throws IOException {
        // Read the filename from the command line argument
        //File file = new File(args[0]);
        //Uses a descriptive file name only using the name of the file we are getting from. That way it is secure characters and not unsafe characters
        File file = new File("Email_addresses_20210205.txt");// (IDS08-J)


        String filename = args[0];
        //FIO16-J
        //getting the canonical path for the file, so the program knows where to look to find the file
        String canonicalPath = file.getCanonicalPath();

        //FIO16-J
        //verification of file location.
        //if the file does not match the expected location, throws excpetion
        try {
            if (!canonicalPath.equals("P:\\CSC245_Project2_Secured\\Email_addresses_20210205.txt")) {
                canonicalPath = " ";
                throw new Exception("This file is not recognized.");
            }

        } catch (Exception e) {
            System.out.println("File type not supported. Please try again.");
        }


        //FIO16-J
        //This allows only the path of the document to read and not the ability to write the file.
        new FilePermission(canonicalPath, "read");
        //printing the path, then the conical path to show the difference.
        //System.out.println("Path: " + file.getPath() );
        //System.out.println("Canonical path: " + canonicalPath + "\n");

        BufferedReader inputStream = null;

        String fileLine;

        // Create a final list, to store different black listed patterns.
        // Created as final so other classes cannot instantiate the list to add or delete elements
        final List<Pattern> blacklist = new ArrayList<>(); // IDS01-J
        blacklist.add(Pattern.compile("[!#$%^*&<>]")); // IDS01-J
        blacklist.add(Pattern.compile("(@)\\1+")); // IDS01-J
        blacklist.add(Pattern.compile("(\\.)\\1+")); // IDS01-J

        if (!check_path(filename)) { //Whitelist Path
            System.out.println("Check file name in arguments and try again.");
        } else {


            try {
                inputStream = new BufferedReader(new FileReader(filename));

                System.out.println("Email Addresses:");
                // Read one Line using BufferedReader
                while ((fileLine = inputStream.readLine()) != null) {
                    StringBuilder sb = new StringBuilder(fileLine.length()); //(IDS08-J)
                    for (int i = 0; i < fileLine.length(); ++i) {//(IDS08-J)
                        char ch = fileLine.charAt(i);//(IDS08-J)
                        if (Character.isLetterOrDigit(ch) || ch == ' ' || ch == '\'') {//(IDS08-J)
                            sb.append(ch);//(IDS08-J)
                        }
                    }
                    filename = sb.toString();//(IDS08-J)

                    String regex = "(.*? +public\\[\\d+\\] +.*" + filename + ".*)";//(IDS08-J)


                    // Normalize before validation
                    String s = Normalizer.normalize(fileLine, Normalizer.Form.NFC); // IDS01-J

                    try {
                        // for loop to test each blacklisted patter/characters
                        for (Pattern pattern : blacklist) { // IDS01-J
                            Matcher matcher = pattern.matcher(s); // IDS01-J

                            // if the loop finds a blacklist, throws an IllegalStateException
                            if (matcher.find()) { // IDS01-J
                                throw new IllegalStateException("Invalid email provided"); // IDS01-J
                            }
                        }
                    } catch (IllegalStateException e) {
                        System.out.println("Input exception: " + e.getMessage());
                    }

                    // Attempt to print the validated emails.
                    try { //ISD51-J
                        System.out.println(validate("E-mail", s)); //ISD51-J
                    } catch (SecurityException e) { //ISD51-J
                        System.out.println("Output exception: " + e.getMessage()); //ISD51-J
                    }
                }


                } catch(IOException io){
                    System.out.println("File IO exception" + io.getMessage());
                    //ERROR01-J
                    //reviling as little as possible but helpful to a Dev, having "A" in the throw message
                    // will theoretically let the Dev know which error to focus on.
                    System.out.println("Invalid File");

                } finally{
                    // Need another catch for closing
                    // the streams
                    try {
                        if (inputStream != null) {
                            inputStream.close();
                        }
                    } catch (IOException io) {
                        System.out.println("Issue closing the Files" + io.getMessage());
                        //ERROR01-J
                        //reviling as little as possible but helpful to a Dev. having "B" in the throw message
                        // will theoretically let the Dev know which error to focus on.
                        System.out.println("Invalid file");

                    }

                }
            }
        }
        private static boolean check_path (String filename){ //Whitelist Path
            File f = new File(filename);
            String path;
            try {
                path = f.getCanonicalPath();

                if (!path.equals(WHITELISTED_PATH + filename)) {
                    return false;
                } else {
                    return path.contains(WHITELISTED_PATH);
                }
            } catch (IOException io) {
                System.out.println("File name in arguments is incorrect" + io.getMessage());
            }
            return false;
        }
    }


