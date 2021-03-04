<?php

class User{
    private $conn;
    private $table_name = "users";

    public $id;
    public $firstname;
    public $lastname;
    public $email;
    public $password;

    public function __construct($db){
        $this->conn = $db;
    }
    function create(){
    
        // insert query
        $query = "INSERT INTO " . $this->table_name . "
                SET
                    firstname = :firstname,
                    lastname = :lastname,
                    email = :email,
                    password = :password";
    
        // prepare the query
        $stmt = $this->conn->prepare($query);
    
        // sanitize
        $this->firstname=htmlspecialchars(strip_tags($this->firstname));
        $this->lastname=htmlspecialchars(strip_tags($this->lastname));
        $this->email=htmlspecialchars(strip_tags($this->email));
        $this->password=htmlspecialchars(strip_tags($this->password));
    
        // bind the values
        $stmt->bindParam(':firstname', $this->firstname);
        $stmt->bindParam(':lastname', $this->lastname);
        $stmt->bindParam(':email', $this->email);
    
        // hash the password before saving to database
        $password_hash = password_hash($this->password, PASSWORD_BCRYPT);
        $stmt->bindParam(':password', $password_hash);
    
        // execute the query, also check if query was successful
        if($stmt->execute()){
            return true;
        }else{
    
        return false;
        }

    }
    function emailExists(){

        $query = "SELECT id, firstname, lastname, password FROM " . $this->table_name . " WHERE email = ? LIMIT 0,1";

        $stmt = $this->conn->prepare($query);

        $this->email=htmlspecialchars(strip_tags($this->email));

        $stmt->bindParam(1, $this->email);

        $stmt->execute();
        
        $num = $stmt->rowCount();

        if ($num>0) {
            # code...
            $row = $stmt->fetch(PDO::FETCH_ASSOC);

            $this->id = $row['id'];
            $this->firstname = $row['firstname'];
            $this->lastname = $row['lastname'];
            $this->password = $row['password'];

            return true;
        }
        return false;
    }

}
?>