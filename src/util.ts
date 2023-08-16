const registeredUsers = new Map();

function addToUserProfile(username: string){
    registeredUsers.set(username, {});
}

function getUserProfile(username: string){
    return registeredUsers.get(username);
}

export{ addToUserProfile, getUserProfile }