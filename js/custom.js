

// The Like AJAX function to increment likes
function like(post_id, user_logged_in, author, type) {

    if (user_logged_in === "") {
        alert("Need to login to " + type);
        return;
    }

    if (user_logged_in === author) {
        console.log("No ajax should happen, author and liker same!");
        alert("You cannot " + type + " your own post");
    }

    else {
        $.ajax({
            type: "POST",
            url: "/post-stats-update/",
            data: {
                post_id: post_id,
                user_id: user_logged_in,
                type: type
            },
            success: function(result) {
                var obj = JSON.parse(result);

                if (obj.error) {
                    alert(obj.error);
                    return;
                }
                else {
                    var str = "<likedislike>";
                    str = str + " " + obj.count;
                    str += "</likedislike>";

                    document.getElementById(type + "-button").innerHTML = str;
                }
            },
            error: function(result) {
                alert("AJAX error!");
            }
        });
    }
};



// Adding tooltip to Login/Signup and Scroll-to-top
// functionality
$(document).ready(function(){

    // Login-signup tooltip
    $('#login-signup').hover(function(){
        $('#login-signup').tooltip('show');
    }, function(){
        $('#login-signup').tooltip('hide');
    });

    $('#login-signup').click(function () {
        $(this).tooltip('hide');
    });



     $(window).scroll(function () {
            if ($(this).scrollTop() > 100) {
                $('#back-to-top').fadeIn();
            } else {
                $('#back-to-top').fadeOut();
            }
        });
        // scroll body to 0px on click
        $('#back-to-top').click(function () {
            $('#back-to-top').tooltip('hide');
            $('body,html').animate({
                scrollTop: 0
            }, 800);
            return false;
        });
        $('#back-to-top').tooltip('show');

});