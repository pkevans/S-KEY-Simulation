import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.math.BigInteger;
import java.util.*;

//Author: Patricia Evans
//Date: March 15, 2017

public class Simulation {

	public static void main(String[] args) throws NoSuchAlgorithmException {
		
		//Secret key, W
		String keyW = "ABCDEFGHIJKLMNOP";
		//List of hash chained passwords
		ArrayList<String> passwordList = new ArrayList<String>();
		
		System.out.println("One Time Password Generation: \n");
		oneTimePassGen(keyW, passwordList);
		
		System.out.println("One Time Password Authorization: \n");
		oneTimePassAuth(passwordList);	

	}
	
	public static void oneTimePassGen(String key, ArrayList<String> arr) throws NoSuchAlgorithmException{
		
		//Convert byte to String(32)
		BigInteger bigInt;
		String hashText = "";
		
		MessageDigest md = MessageDigest.getInstance("SHA-1");
		byte data[] = key.getBytes();
		
		////Begin Hash chaining H^n(W), where n = 5
		int n = 5;
		
		for(int i = 0; i < n; i++){
			
			md.update(data);
			data = md.digest();
			bigInt = new BigInteger(1, data);
			hashText = bigInt.toString(32);
			arr.add(hashText);
			
			//Convert back to bytes for authentication
			data = hashText.getBytes();
			
		}

		//Print out password list
		System.out.println("Password list: " + arr);
		
		//Remove H^1(W) to H^4(W)
		arr.clear();
		arr.add(hashText);
		
		//Print out H^5(W)
		System.out.println("H^5(W): " + arr + "\n");
		
	}
	
	public static void oneTimePassAuth(ArrayList<String> arr) throws NoSuchAlgorithmException{
		
		//Convert byte to String(32)
		BigInteger bigInt;
		String hashText = "";
		
		//Authenticating H^4(W), H^n-1(W) compare to H^n(W)
		Scanner scan = new Scanner(System.in);
	
		System.out.println("Authenticate H^4(W): ");
		String password1 = scan.next();
		
		MessageDigest md = MessageDigest.getInstance("SHA-1");
		byte data[] = password1.getBytes();
		
		//Hash chaining H^4(W)
		md.update(data);
		data = md.digest();
		bigInt = new BigInteger(1, data);
		hashText = bigInt.toString(32);
			
		//Comparing and validating password. Removing old password.
		if(arr.get(0).equals(hashText)){
			
			System.out.println("Success!");
			System.out.println("Scratch H^5(W): " + arr.get(0));
			arr.remove(0);
			arr.add(password1);
			System.out.println("H^4(W) stored in Password List: " + arr + "\n");
			
		}
    
		else{
			
			System.out.println("Incorrect. Unable to authenticate.\n");
			
		}
			
		//Authenticating H^3(W), H^n-2(W) compare to H^n-1(W)
		System.out.println("Authenticate H^3(W): ");
		String password2 = scan.next();
	
		data = password2.getBytes();
		
		//Hash Chaining H^3(W)
		md.update(data);
		data = md.digest();
		bigInt = new BigInteger(1, data);
		hashText = bigInt.toString(32);
			
		//Comparing and validating password. Removing old password.
		if(arr.get(0).equals(hashText)){
			
			System.out.println("Success!");
			System.out.println("Scratch H^4(W): " + arr.get(0));
			arr.remove(0);
			arr.add(password2);
			System.out.println("H^3(W) stored in Password List: "+ arr + "\n");
			
		}
		
		else{
			
			System.out.println("Incorrect. Unable to authenticate.");
			System.out.println("Re-start the program to retry.\n");
			
		}
	
		System.out.println("Program has ended.\n");
		scan.close();
	}

}
