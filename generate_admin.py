# generate_admin.py
from flask_bcrypt import Bcrypt
bcrypt = Bcrypt()

# =========================================================
# >> Yaha a-afno FINAL password ra FINAL secret key halnuhos <<
my_final_password = 'RazanIsAdmin'      # Hajurko Final Password
my_final_secret_key = 'RD_Cafe_2024'  # Hajurko Final Secret Key
# =========================================================

# Hash generate garne
password_hash = bcrypt.generate_password_hash(my_final_password).decode('utf-8')
secret_key_hash = bcrypt.generate_password_hash(my_final_secret_key).decode('utf-8')

print("\n--- COPY THESE FINAL HASHED VALUES ---")
print(f"\nFINAL Password Hash for '{my_final_password}':")
print(password_hash)
print(f"\nFINAL Secret Key Hash for '{my_final_secret_key}':")
print(secret_key_hash)
print("\n-------------------------------------")