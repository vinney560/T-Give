document.addEventListener("DOMContentLoaded", function() {
    let collapsibles = document.querySelectorAll(".collapsible");
    
    collapsibles.forEach(function(coll) {
        coll.addEventListener("click", function() {
            this.classList.toggle("active");
            let content = this.nextElementSibling;
            if (content.style.display === "block") {
                content.style.display = "none";
            } else {
                content.style.display = "block";
            }
        });
    });
});

function banUser(userId) {
    if (confirm("Are you sure you want to ban this user?")) {
        alert("User " + userId + " has been banned.");
    }
}

function deleteUser(userId) {
    if (confirm("Are you sure you want to delete this user?")) {
        alert("User " + userId + " has been deleted.");
    }
}

function editProduct(productId) {
    alert("Editing Product ID: " + productId);
}

function deleteProduct(productId) {
    if (confirm("Are you sure you want to delete this product?")) {
        alert("Product " + productId + " has been deleted.");
    }
}

function updateOrderStatus(orderId, status) {
    alert("Order " + orderId + " status updated to: " + status);
}

function deleteOrder(orderId) {
    if (confirm("Are you sure you want to delete this order?")) {
        alert("Order " + orderId + " has been deleted.");
    }
}