class loging():

    path = None # samen folder as the code
    name_file = "logs_detectie.txt"

    def make_file():
        open(loging.name_file,'w')


    def write_to_file(text):
        done = False

        while not(done):
            try:
                with open(loging.name_file,'r') as file:
                    data = file.read() 

                if (data == ""):
                    with open(loging.name_file,'w') as file:
                        file.write(text + "\n" )
                else:
                    with open(loging.name_file,'w') as file:
                        file.write(data + "\n" + text)
                done = True
            except:
                loging.make_file()
            
            