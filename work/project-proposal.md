**CSC 330 ⏺ Software Design & Development**		     	   Spring 2026  
Team project proposal

**Recipe Management System**

**Due: 	11:59pm on 03.02.2025**   
**(no late submissions will be accepted for team assignments)**

**Upcoming milestones**

1. Team meetings with instructor 03/03 to discuss proposal and progress on SRS  
2. Draft of SRS due by beginning of class on March 11  
3. Team presentation of project proposal and SRS on March 11

**Team selection**

Team assignments have been completed, we have the following 6 teams:

**Frontend Devs** \- Patrick, Isaiah, Francis  
**The Champions** \- Noah, Tasnim, Ean  
**Copy+Paste** \- Javan, Zach, Chizindu  
**Error 404** \- Hans, Dheylin, Benjamin  
**The CCs** \- Allie, Max, Jessica  
**110** \- Keith, Camila, Kevin, Raeann

**Strategy to develop a great proposal**

Each team member should **read this document *thoroughly*** before the first team brainstorming session.  Go to your first team meeting with your own notes, ideas and questions.  To help synthesize all the ideas and come up with a coherent proposal it would be a good idea if one or two team members act as coordinators (this does not mean the proposal will only reflect the coordinators' ideas while everyone else just goes along; a good project is one where every team member takes ownership of the project).   Developing a thoughtful and well-written proposal will probably require more than one synchronous team meeting, or a combination of short synchronous meetings and offline message exchanges.  Start early to give time for ideas to be refined and improved.  Initial ideas are rarely great. Great work is often the end result of iterative improvement. 

## **Background**

In many households and small community organizations, the management of culinary knowledge—recipes, dietary restrictions, and meal planning—is often fragmented. Recipes are scattered across physical cards, bookmarked websites, and disparate email chains. This lack of centralization makes it difficult for families or small groups to collaborate on meal preparation, maintain consistency in "signature" dishes, or scale quantities for larger gatherings.

Furthermore, as dietary needs become more complex (e.g., allergies, veganism, gluten-free requirements), a simple list of instructions is no longer sufficient. Modern culinary management requires a system that allows for **collaborative versioning**, where a "Master Recipe" can be adapted or "forked" for different needs, and where data like ingredient quantities can be dynamically manipulated based on the number of guests. A streamlined, collaborative recipe system is essential for families and communities to preserve their culinary heritage while adapting to modern nutritional and social needs.

## **Project Proposal: "The Open Kitchen" Recipe Box**

You are charged with developing a collaborative recipe management system that addresses the organizational challenges mentioned above. To limit the scope, your team should focus on a "Community or Family" operating environment. Your system should enable users to not only store recipes but to interact with them as dynamic data.

How your system helps a family or group stay organized, how it handles the "social" aspect of sharing tips on a specific dish, and why a user would prefer this over a simple physical notebook are the core value propositions you should emphasize.

### **Minimum Required Functionality**

To ensure your project meets the technical complexity expected for the course, the system must include the following:

1. **Authenticated User Roles:**  
   * **Contributor:** A regular user who can create, view, and "fork" recipes. They can also leave comments or tips on others' recipes.  
   * **Curator (Administrator):** An administrative user who can manage users (create new, delete etc) and manage the notification settings for each user (email address). Additionally, the administrator can also manage lookup lists such as the units allowed (grams, ounces etc) that will be permitted.  
2. **Recipe Types & Data Requirements:**  
   * The system must support at least two "Template" types with different data requirements:  
     * **Standard Recipe:** Requires ingredients (item \+ quantity), step-by-step instructions, and prep/cook times, additional tags like category, nut-free, keto etc.  
     * **Quick Tip:** A shorter entry focusing on a specific culinary hack or ingredient replacement (e.g., "Replacing eggs with applesauce in baking").  
3. **Dynamic Ingredient Scaling:**  
   * A user should be able to view a recipe and input a "Serving Size" (e.g., 4 people vs. 12 people). The system must automatically recalculate the ingredient quantities in the database view based on this input.  
4. **Recipe "Forking" & Versioning:**  
   * The system should allow a user to "Fork" an existing recipe. This creates a new copy of the recipe in the user's personal profile, allowing them to make amendments (e.g., "Mom's Chili \- Extra Spicy Version") while maintaining a link back to the original "Master" recipe.   
5. **Personalized Dashboard (The "My Kitchen" View):**  
   * Users must have a central view of all recipes they have authored, recipes they have "forked," and recipes they have "saved" for later.  
6. **Search and Filtering:**  
   * The system must allow users to filter recipes by multiple criteria, such as "Category" (Appetizer, Dessert), "Dietary Tag" (Nut-free, Keto), or "Total Time."  
7. **Social Feedback Loop:**  
   * Users should be able to "Review" a recipe they have tried, including a star rating and a text comment. The recipe owner should receive a notification when a new review is posted.  
8. **Automated Notifications:**  
   * The system should use an email or notification mechanism to alert users of specific events (e.g., "User X just forked your recipe" or "User Y left a comment on your Apple Pie").  
9. **Curator Reports:**  
   * The Curator (Admin) should be able to generate reports on system activity, such as:  
     * The "Most Forked" recipes (indicating popularity).  
     * A list of all recipes containing a specific allergen (e.g., "Peanuts") for safety auditing.  
     * User activity logs (who has contributed the most recipes in the last 30 days).

Your first task as a team is to define your vision for the application and how the features you propose will serve the needs of the target population.  You should not be overly concerned about whether it will be possible to implement all the features you’ve identified in this proposal by the end of the semester.  As the semester progresses, your instructor will work with your team to scope the project appropriately and identify what a minimally viable product would be.  

**Your Team Assignment**

You are to develop a proposal (2 \- 3 pages, single spaced, 1-inch margins) that lays out **your team’s vision** of your project and spells out the main features you will focus on.  The proposal should address the questions below.  In writing the proposal, address the questions as part of a narrative and include section headers for the various elements of the proposal.  Please avoid having your proposal read as a Q\&A.   It should flow as a single document.    

1. What’s the project motivation?  In one or two sentences, summarize the objective of your project.    
2. Describe your potential users and usage scenario.    
3. What specific user needs will your project address?  The more focused it is, the easier it will be to manage the project and be successful at producing a cohesive and viable project.    
4. Define the user needs by developing **12-15 user stories**.  These should be consistent with the user needs and project objectives.  Be sure to conform to the template of the user story (e.g. as a \<type of user\>, I would like to \<able to do this\> so that I can \<accomplish this goal\>).    See video resources below.    
5. What are the core features of your system?  Are they consistent with the needs of the user?   List the features and include a short description for each.   While the user stories are written from the perspective of the user, core features are written from the perspective of the system.    
6. You may optionally include diagrams if they help explain your vision better.    
7. Describe your work plan.  If you were to break up the development into 3 successive phases (sprints), what will your implementation goals for each phase be?  You can write them in relation to the user stories you developed in \#5.    
8. What might be some of the metrics that you would like to track (before and after) in order to measure the success of the project? For example, what would be the time \+ headcount needed for a manual process Vs an systemic solution?

**Video resources**  
Before attempting to develop user stories (Item 4 above, watch the following YouTube videos on agile development and user stories in the order shown:

* What is Agile? (12 minutes) [https://youtu.be/Z9QbYZh1YXY](https://youtu.be/Z9QbYZh1YXY)   
* Introduction to SCRUM (8 minutes) – SCRUM is one of the most common agile development practices: [https://youtu.be/9TycLR0TqFA](https://youtu.be/9TycLR0TqFA)  
* What is SCRUM? (8 minutes): [https://youtu.be/m5u0P1WPfvs](https://youtu.be/m5u0P1WPfvs)  
* Agile User Stories (7 minutes): [https://youtu.be/apOvF9NVguA](https://youtu.be/apOvF9NVguA)  
* **Bonus TEDx Talk**: Mind mapping as a technique to help you brainstorm in a team (16 minutes): [https://youtu.be/5nTuScU70As](https://youtu.be/5nTuScU70As)

**Submission**  
As a suggestion, your team might want to develop this document as a Google Doc where all team members are editors and changes to the document can be viewed in real time.  Once you’re done writing and proofreading, export the document as a pdf file and submit it in Teams.  

**All team members are required to make their own submission of the same copy of the document that the team developed collectively. Submit the proposal as a PDF file.**   This is an acknowledgement that each team member is aware of what the team is proposing.    At the top of the document, include the names of all team members who contributed to writing the proposal.  Be sure to proofread the proposal and style it appropriately so it’s easy to follow. 
