USER MANAGEMENT SYSATEM FINAL PROJECT

LEARNING’S FROM THIS COURSE 
With this Web Systems Development course, I learned how to effectively employ Git for version control like creating a branch, committing changes, resolving conflicts, and collaborating on projects using GitHub. I also learned about GitHub Actions to automate tasks like testing and deployment. This helped me understand how professional groups of developers manage code, keep track of changes, and collaborate effortlessly in real software development.
CLOSED ISSUES
1)	Fixed the Docker and Workflow Files:
•	Removed hard-coded environment variables and dependencies from the Dockerfile so that the application can compile and run suitably within containerized environments.
•	Updated the workflow YAML file with the steps for linting, testing, and deployment so that automated build and test happen on push.
•	Fixed some issues with Dockerfile and GitHub Actions Workflow files for proper CI/CD pipeline functionality.
•	Link : https://github.com/rukhmanand99/user_management_project/tree/1-fix-the-docker-and-workflow-files

2)	User password Issue:
•	Comprehensive tests included to ensure that password validation is working correctly in various scenarios.
•	Enforced strong password policy with enhanced password validation for minimum password length, password complexity (e.g., use of special and alphanumeric characters), and no password reuse.
•	Link: https://github.com/rukhmanand99/user_management_project/tree/3-user-password-issue

3)	Email Verification Issue:
•	Upgraded validation rules so that emails are formatted and validated correctly and user IDs are made unique.
•	Added error messages for incorrect input and unit tests for validating a user ID and an e-mail address.
•	Link: https://github.com/rukhmanand99/user_management_project/tree/5-email-verification-issue

4)	Token Process Issue:
•	Implemented a retry mechanism for retrieving tokens when the tokens for the authenticated users have expired.
•	Fixed a bug that caused expired tokens to return endpoint errors
•	Link: https://github.com/rukhmanand99/user_management_project/tree/7-token-process-issue

5)	Professional Issue:
•	We investigated the API endpoint that is used for updating the user information and fixed the logic for the fields to correctly update the database.
•	Fixed a bug where the user model is_professional field was not being updated correctly.
•	Link: https://github.com/rukhmanand99/user_management_project/tree/9-professional-issue

NEW FEATURE: USER SEARCH AND FILTERING
User Search and Filtering Feature is an added feature to the User Management System that allows for efficient searching and management of the users by administrators. It provides a configurable searching and filtering facility for improving the utility of the system.
Implementation:
•	Users can be filtered by role (e.g., USER, MANAGER, ADMIN), account_status (e.g., ACTIVE, INACTIVE), and date ranges for registration (start_date and end_date).
•	Ability to search for users on partial match of email address and username.
•	Utilizes a reusable service-layer to perform queries in order to ensure scalability and consistency.
LINK: https://github.com/rukhmanand99/user_management_project/tree/New_Feature


NEWLY ADDED TEST CASES:
Newly added Test cases
Test Case 1: Confirms password policies, requiring adherence to security standards such as length, special character, and upper- and lower-case letters.
Test Case 2: Tests for a user with a valid email from the database.
Test Case 3: Tests that a fetch of a user with an incorrect e-mail is None.
Test Case 4: Testing for a user based on their valid unique identifier.
Test Case 5: Verifies that the creation of the user is valid and provides the proper roles (ADMIN to the initial user, AUTHENTICATED to other users). Also ensures that email verification is started.
Test Case 6: Tests that alter a user's role.
Test Case 7: IsValid to lock a user account for limiting access.
Test Case 8: Tests a user is deleted and the operation returns True.
Test Case 9: Test that retrieving a user with an incorrect ID UUID returns None.
Test Case 10: Supports account lockout for denial of access.

Git Hub Link :https://github.com/rukhmanand99/user_management_project
Docker Link :https://hub.docker.com/repository/docker/rukhmanandreddy/hm10/tags
