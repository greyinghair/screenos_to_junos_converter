def sanity_check_naming(name): # Remove invalid characters from a string

        # Set address_name var to same as address but replace anything in invalid_characters with "_" so works with Junos
    invalid_characters = [" ", ".", "/", "\"", "\'", "\\", "!", "?", "[", "]", "{", "}", "|", "(", ")", "-", "+"]
    
    for chars in invalid_characters:
        name = name.replace(chars, "_").lower()
    
    # Alpha numeric list for characters that Junos names are allowed to START with
    alpha_num = ['a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','0','1','2','3','4','5','6','7','8','9']

    # Only if start (index 0 / 1st character) of name is NOT alphanumeric
    if name[0].lower() not in alpha_num:
        amended_name = "" # Blank var but populated 4 lines down so can be returned to function outside of loop
        # loop to account for name starting with more than 1 non valid character such as ..dan or //dan
        while name[0].lower() not in alpha_num:
            amended_name = name[1:] # Slice from index 1 onwards, ie removal of 1st character
            # print(f'address starting with invalid character = {amended_name}')    #   Debug invalid naming
            name = amended_name # Change name to use the corrected string to stop loop when string starts alphanumeric
        return amended_name

    # Else, return name after earlier check and removal of non valid characters
    else:
        return name