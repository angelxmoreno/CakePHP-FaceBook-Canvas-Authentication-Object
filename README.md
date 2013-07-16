CakePHP-FaceBook-Canvas-Authentication-Object
=============================================

a CakePHP Authentication object for FaceBook Apps for use with the AuthComponent

## Intro
In order for the FaceBookCanvas authentication object to work, the FaceBookCanvas component must be loaded. This is because of the natured of how the
AuthComponent works combined with the way that FaceBook apps send request data for authentication. When you first hit a FaceBook app a post is sent to
the application. FaceBook does not send this post data again. This means that we need to capture the post data prior to any attempt to authenticate a user.
The authorization objects currently have no callbacks that the AuthComponent can run on load. This means that they can not be used to capture the initial
request sent by FaceBook. This is where the component comes in. Upon loading,  the component saves the post data to a session and then attempts to log
the user in. If the current user has previously granted the app permission, the the post data should have all we need to log the user in.
