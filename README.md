usage:

```
import git
token = <your token>
git_info = git.GitInfo(
	auth=token
)
git.push(<git url>, <folder name>, git_info)
```