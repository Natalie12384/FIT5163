class User{
    constructor(username, password_hash, salt){
        this.username = username;
        this.salt = salt;
        this.password_hash = password_hash;
    }
}
module.exports = User;