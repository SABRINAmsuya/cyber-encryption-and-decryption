import tkinter as tk
import hashlib

root = tk.Tk()
root.title("First GUI")
title_label = tk.Label(root, text="Name: SABRINA A MSUYA")
title_label.grid(row=0, column=0)

registration_label = tk.Label(root, text="Reg.No: 2102302118791")
registration_label.grid(row=0, column=1)
message_label = tk.Label(root, text="Enter Message:")
message_label.grid(row=1, column=0)
message_entry = tk.Entry(root)
message_entry.grid(row=1, column=1)

signature_label = tk.Label(root, text="Enter Signature:")
signature_label.grid(row=2, column=0)
signature_entry = tk.Entry(root)
signature_entry.grid(row=2, column=1)

key_label = tk.Label(root, text="Enter Key:")
key_label.grid(row=3, column=0)
key_entry = tk.Entry(root, show="*")
key_entry.grid(row=3, column=1)

signature = "sabrina";

def encryption():
    global message, hashed_signature_
    message = message_entry.get()
    key = key_entry.get().encode('utf-8')
    signature_ = signature_entry.get()
    hashed_message = hashlib.sha256(message.encode('utf-8')).hexdigest()
    #hashed_signature_first_ = hashlib.sha256(signature_.encode('utf-8')).hexdigest()
    hashed_key = hashlib.sha256(key).hexdigest()

    encrypted_message_text.delete(1.0, tk.END)
    encrypted_message_text.insert(tk.END, hashed_message)
    encrypted_signature_text.delete(1.0, tk.END)
    encrypted_signature_text.insert(tk.END, signature_)

    send.config(state=tk.NORMAL)


def sender():
    encrypted_message = encrypted_message_text.get(1.0, tk.END)
    encrypted_signature = signature_entry.get()

    second_gui = tk.Toplevel(root)
    second_gui.title("Second GUI")

    received_message_label = tk.Label(second_gui, text="Encrypted Message:")
    received_message_label.grid(row=0, column=0)
    received_message_text = tk.Text(second_gui, height=2, width=30)
    received_message_text.insert(tk.END, encrypted_message)
    received_message_text.grid(row=0, column=1)

    received_signature_label = tk.Label(second_gui, text="authentication Signature:")
    received_signature_label.grid(row=1, column=0)
    received_signature_text = tk.Text(second_gui, height=2, width=30)
    received_signature_text.insert(tk.END, encrypted_signature)
    received_signature_text.grid(row=1, column=1)
    
    def decrypt():
        entered_key = decryption_key_entry.get().encode('utf-8')
        entered_key_hash = hashlib.sha256(entered_key).hexdigest()

        if entered_key_hash == hashlib.sha256(key_entry.get().encode('utf-8')).hexdigest():
            decrypted_message = message  # Retrieve the original message
            decrypted_message_label.config(text=f"Decrypted Message: {decrypted_message}")
        else:
            decrypted_message_label.config(text="Incorrect Key!")


    def verification():
        if  signature == signature_entry.get():
            verify_result_label.config(text=signature)
        else:
            verify_result_label.config(text="Signature does not match")

    decryption_key_label = tk.Label(second_gui, text="Enter Key to Decrypt:")
    decryption_key_label.grid(row=2, column=0)
    decryption_key_entry = tk.Entry(second_gui, show="*")
    decryption_key_entry.grid(row=2, column=1)

    decrypt_button = tk.Button(second_gui, text="Decrypt", command=decrypt)
    decrypt_button.grid(row=3, column=0)

    verify_button = tk.Button(second_gui, text="Verify", command=verification)
    verify_button.grid(row=4, column=0)

    decrypted_message_label = tk.Label(second_gui, text="")
    decrypted_message_label.grid(row=3, column=1)

    verify_result_label = tk.Label(second_gui, text="")
    verify_result_label.grid(row=4, column=1)



encrypt_button = tk.Button(root, text="Encrypt", command=encryption)
encrypt_button.grid(row=4, column=0)

encrypted_message_label = tk.Label(root, text="Encrypted Message:")
encrypted_message_label.grid(row=5, column=0)
encrypted_message_text = tk.Text(root, height=2, width=30)
encrypted_message_text.grid(row=5, column=1)

encrypted_signature_label = tk.Label(root, text="authentication Signature:")
encrypted_signature_label.grid(row=6, column=0)
encrypted_signature_text = tk.Text(root, height=2, width=30)
encrypted_signature_text.grid(row=6, column=1)

send= tk.Button(root, text="Send", command=sender, state=tk.DISABLED)
send.grid(row=7, column=0)









root.mainloop()