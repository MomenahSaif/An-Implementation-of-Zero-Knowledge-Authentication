import hashlib
import random

class AuthenticationSystem:
    def __init__(self):
        self.users = {}
        self.G = [random.randint(0, 9) for _ in range(155)]
        self.g0 = [random.randint(0, 9) for _ in range(155)]

    def register_user(self, username, password):
        # Check if the username already exists
        if username in self.users:
            print("\033[1;31mError: Username already exists!\033[0m")

            return

        password_hash = hashlib.sha256(password.encode()).hexdigest()
       
        # Compute the public key Y = g0^x
        x = int(password_hash, 16)  # Convert the hash to integer
        Y = [pow(g, x, len(self.G)) for g in self.g0]  # Computing g0^x mod |G|

        # Store the user's information
        self.users[username] = {'Y': Y, 'login_attempts': 0}
        print("\033[1;33;40m" + "********************************\n" + "\033[0m")
        print("\033[1;40m User registered successfully!\n\033[0m")
        print("\033[1;33;40m" + "********************************\n" + "\033[0m")
       
        print("\033[1;35;40m" + "******************************************\n" + "\033[0m")
        print("\033[1;32;40m" + "            Password HASH \n" + "\033[0m")
        print("\033[1;35;40m" + "******************************************\n" + "\033[0m")
        print("\033[1;34mHash:\033[0m", "\033[1;32m", password_hash, "\033[0m")
        print("\n")
       
       
        print("\033[1;35;40m" + "******************************************\n" + "\033[0m")
        print("\033[1;32;40m" + "             Public Key \n" + "\033[0m")
        print("\033[1;35;40m" + "******************************************\n" + "\033[0m")
        print("\033[1;34mPublic key:\033[0m", "\033[1;32m", "".join(map(str, Y)), "\033[0m")
        print("\n")

       
    def authenticate_user(self, username, password):
        if username in self.users:
           if self.users[username].get('locked', False):
               print("\033[1;35;40m" + "******************************************\n" + "\033[0m")
               print("\033[1;32;40m" + "             LOGIN FAILED \n" + "\033[0m")
               print("\033[1;35;40m" + "******************************************\n" + "\033[0m")
               print("User is locked. Contact administrator.")
               return

           self.users[username]['login_attempts'] += 1

           if self.users[username]['login_attempts'] > 3:
               print("\033[1;35;40m" + "******************************************\n" + "\033[0m")
               print("\033[1;31;40m" + "            USER IS LOCKED \n" + "\033[0m")
               print("\033[1;35;40m" + "******************************************\n" + "\033[0m")
               del self.users[username]
               return

           password_hash = hashlib.sha256(password.encode()).hexdigest()
           x = int(password_hash, 16)
           Y = self.users[username]['Y']
           
           r = random.randint(10**(155-1), 10**155-1)
           print("\033[1;35;40m" + "***********************************************************************************\n" + "\033[0m")
           print("\033[1;32;40m" + "      r, a private random number specific to this authentication attempt              \n" + "\033[0m")
           print("\033[1;35;40m" + "***********************************************************************************\n" + "\033[0m")
           print("\033[1;34mr: \033[0m", "\033[1;33m", r, "\033[0m", "\n")
           # Compute T = g0^r
           T = [pow(g, r, len(self.G)) for g in self.g0]

           # Generate a random challenge 'a'
           a = random.randint(10**(155-1), 10**155-1)
           print("\033[1;35;40m" + "**************************************************\n" + "\033[0m")
           print("\033[1;32;40m" + "          a, a random challenge            \n" + "\033[0m")
           print("\033[1;35;40m" + "**************************************************\n" + "\033[0m")
           print("\033[1;34ma: \033[0m", "\033[1;33m", a, "\033[0m", "\n")
           # Compute c = hash(Y || T || a)
           concatenated_data = "".join(map(str, Y + T + [a]))
           c = hashlib.sha256(concatenated_data.encode()).hexdigest()

           # Compute z = r - cx
           z = (r - int(c, 16) * x)

           # Send the pair (c, z) to the server
           user_response = (c, z)

           # Server checks if hash(Y || T' || a) matches c
           T_prime = [(pow(Y[i], int(c, 16), len(self.G)) * pow(self.g0[i], z, len(self.G))) % len(self.G) for i in range(len(Y))]
           concatenated_data_prime = "".join(map(str, Y + T_prime + [a]))
           c_prime = hashlib.sha256(concatenated_data_prime.encode()).hexdigest()
           print("\033[1;35;40m" + "***********************************************************************************\n" + "\033[0m")
           print("\033[1;32;40m" + "                             z = r − cx             \n" + "\033[0m")          
           print("\033[1;35;40m" + "***********************************************************************************\n" + "\033[0m")
           print("\033[1;34mz: \033[0m", "\033[1;33m", z, "\033[0m", "\n")
           
           
           print("\033[1;35;40m" + "***********************************************************************************\n" + "\033[0m")
           print("\033[1;32;40m" + "                            T' = (Y^c)*(g0^z)            \n" + "\033[0m")          
           print("\033[1;35;40m" + "***********************************************************************************\n" + "\033[0m")
           print("\033[1;34mT_prime: \033[0m", "\033[1;33m", "".join(map(str, T_prime)), "\033[0m", "\n")
           
           
           print("\033[1;35;40m" + "***********************************************************************************\n" + "\033[0m")
           print("\033[1;32;40m" + "                             c' = hash(Y ||T'||a)            \n" + "\033[0m")
           print("\033[1;35;40m" + "***********************************************************************************\n" + "\033[0m")
           print("\033[1;34mc_prime: \033[0m", "\033[1;33m", c_prime, "\033[0m", "\n")


           if c_prime == c:
               print("\033[1;35;40m" + "******************************************************************\n" + "\033[0m")
               print("\033[1;32m             Authentication successful for user '{}'!\033[0m\n".format(username))
               print("\033[1;35;40m" + "******************************************************************\n" + "\033[0m")

           else:
               print("\033[1;31mAuthentication failed. Please try again.\033[0m")

        else:
             print("\033[1;31mUSER NOT FOUND.\033[0m")
           
 

def main():

    auth_system = AuthenticationSystem()
    print("\033[1;35;40m" + "********************************************************************************\n" + "\033[0m")
    print("\033[1;32;40m" + "          An Implementation of Zero Knowledge Authentication\n" + "\033[0m")
    print("\033[1;35;40m" + "********************************************************************************\n" + "\033[0m")
    print("\n\033[1;37;42mServer's public key:\033[0m")
    print("\n\033[1;36;40mG: " + "".join(map(str, auth_system.G)) + "\033[0m")
    print("\n\033[1;33;40mg0: " + "".join(map(str, auth_system.g0)) + "\033[0m")
    print("\n")
   
    while True:
        print("\033[1;35;40m" + "******************************************\n" + "\033[0m")
        print("\033[1;32;40m" + "                  Menu \n" + "\033[0m")
        print("\033[1;35;40m" + "******************************************\n" + "\033[0m")
        action = input("\033[1;32;40m**Enter any one of following**\n1. 'R' for registration\n2. 'A' for authentication\n3. 'Q' to quit\n\033[0m")
       


        if action == 'R':
            print("\033[1;35;40m" + "******************************************\n" + "\033[0m")
            print("\033[1;32;40m" + "              Enter Crendentails \n" + "\033[0m")
            print("\033[1;35;40m" + "******************************************\n" + "\033[0m")
            username = input("\033[1;33;40mEnter username: \033[0m")
            while True:
                   password = input("\033[1;32;40mEnter password: \033[0m")
                   if len(password) < 8:
                       print("\033[1;33mPassword must be at least 8 characters long. Please re-enter.\033[0m")

                   else:
                        break
            auth_system.register_user(username, password)
        elif action == 'A':
            print("\033[1;35;40m" + "******************************************\n" + "\033[0m")
            print("\033[1;32;40m" + "              Authentication \n" + "\033[0m")
            print("\033[1;35;40m" + "******************************************\n" + "\033[0m")
           
            username = input("\033[1;34mEnter username for authentication: \033[0m")
            password = input("\033[1;34mEnter password for authentication: \033[0m")
           

            auth_system.authenticate_user(username, password)
        elif action == 'Q':
            print("\033[1;30;43mExiting...\033[0m")

            break
        else:
            print("Invalid action. Please enter 'R', 'A', or 'Q'.")

if __name__ == "__main__":
    main()
