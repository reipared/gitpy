# GitPy

GitPy is a minimal Git implementation written in Python. It provides a command-line interface to perform various Git operations, such as initializing a new repository, adding files to the index, committing changes, displaying object contents, showing the status of the working copy, and pushing changes to a remote Git server.

The main features of GitPy include:
1. Repository Initialization: GitPy allows users to create a new repository with the `init` command. It sets up the necessary directory structure and initializes the repository with an empty master branch.
2. File Management: Users can add files to the index using the `add` command. GitPy calculates the hash of each file and stores it in the object store. The `ls-files` command displays the list of files in the index, along with their mode, hash, and stage number.
3. Committing Changes: The `commit` command enables users to commit the current state of the index to the master branch. It generates a commit object with the corresponding tree object, parent commit reference (if available), author information, and commit message.
4. Object Manipulation: GitPy provides functionality to display the contents of Git objects using the `cat-file` command. Users can specify the object type (commit, tree, blob) or display modes (size, type, pretty) to retrieve the desired information.
5. Status and Diffs: The `status` command shows the status of the working copy, highlighting changed, new, and deleted files. The `diff` command displays the differences between the index and the working copy.
6. Pushing Changes: Users can push the changes from the local master branch to a remote Git server using the `push` command. GitPy communicates with the server, determines the missing objects, and creates a pack file containing all the objects to be pushed.

GitPy is a simplified implementation of Git, aiming to provide users with essential Git functionalities. It serves as an educational tool for understanding the inner workings of Git and can be extended to support additional Git features.
