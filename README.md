# App Server for Google Play Integrity
As the [SafetyNet Attestation API is deprecated and has been replaced by the Play Integrity API](https://developer.android.com/training/safetynet/deprecation-timeline), many mobile solutions will have to migrate to prevent attacks and reduce abuse on their apps.

I had some trouble puting all the pieces together to implement the App Server [as described on the official docs](https://developer.android.com/google/play/integrity/verdict), mainly due the lack of information about the correct dependencies in Java. 

[This StackOverflow thread](https://stackoverflow.com/questions/72193058/google-playintegrity-api-a-nightmare) was really helpfull to solve it, then I've decided to put it all together in a Spring Boot demo project. Hopefully it will help someone else.

The project has an implementation of the App Server that can decrypt and verify the integrity veredict, both on Google's servers (through the Google API) and locally, as well as generate nonces.

All the keys and credentials presented on the properties file and unit tests are fake and meant for test and demonstration only.  
