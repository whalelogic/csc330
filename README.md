# CSC 330: Software Design & Development — Spring 2026

## Team Project Proposal: Recipe Management System


### Upcoming Milestones

1.  **03/03:** Team meetings with instructor to discuss proposal and progress on SRS.
    
2.  **03/11:** Draft of SRS due by beginning of class.
    
3.  **03/11:** Team presentation of project proposal and SRS.
    


### Strategy to Develop a Great Proposal

-   **Read Thoroughly:** Each team member must read this document before brainstorming.
    
-   **Brainstorming:** Bring notes, ideas, and questions to the first meeting.
    
-   **Coordination:** Appoint one or two members to act as coordinators to synthesize ideas.
    
-   **Iteration:** Great work results from iterative improvement. Start early.
    

### Background

In many households and small community organizations, the management of culinary knowledge—recipes, dietary restrictions, and meal planning—is often fragmented. Recipes are scattered across physical cards, bookmarked websites, and disparate email chains. This lack of centralization makes it difficult for families or small groups to collaborate on meal preparation, maintain consistency in "signature" dishes, or scale quantities for larger gatherings.

Furthermore, as dietary needs become more complex (e.g., allergies, veganism, gluten-free requirements), a simple list of instructions is no longer sufficient. Modern culinary management requires a system that allows for collaborative versioning, where a **"Master Recipe"** can be adapted or **"forked"** for different needs.


### Project Proposal: "The Open Kitchen" Recipe Box

You are charged with developing a collaborative recipe management system that addresses these organizational challenges.


#### **Minimum Required Functionality**


**1. Authenticated User Roles**

-   **Contributor:** A regular user who can create, view, and "fork" recipes.
    
-   **Curator (Administrator):** An administrative user who manages users, notification settings, and unit lookup lists (grams, ounces, etc.).
    

**2. Recipe Types & Data Requirements**

-   **Standard Recipe:** Requires ingredients, step-by-step instructions, prep/cook times, and tags (Nut-free, Keto, etc.).
    
-   **Quick Tip:** A shorter entry focusing on a specific culinary hack or ingredient replacement.
    

**3. Dynamic Ingredient Scaling**

-   Users can input a **"Serving Size"**. The system must automatically recalculate ingredient quantities in the database view.
    

**4. Recipe "Forking" & Versioning**

-   Users can "Fork" an existing recipe to their personal profile to make amendments while maintaining a link to the original.
    

**5. Personalized Dashboard (The "My Kitchen" View)**

-   Centralized view of authored, forked, and saved recipes.
    

**6. Search and Filtering**

-   Filter by Category (Appetizer, Dessert), Dietary Tag, or Total Time.
    

**7. Social Feedback Loop**

-   Users can review recipes with a star rating and text comment.
    

**8. Automated Notifications**

-   Email or notification mechanism to alert users of forks or comments.
    

**9. Curator Reports**

-   Generate reports on "Most Forked" recipes, allergen safety audits, and user activity logs.
    

### Team Assignment Requirements

Your proposal (2-3 pages) must address the following narrative elements:

1.  **Project Motivation:** 1-2 sentence summary of the objective.
    
2.  **User Profiles:** Describe potential users and usage scenarios.
    
3.  **User Stories:** Define 12-15 user stories using the template: _As a <type of user>, I would like to <action> so that I can <goal>._
    
4.  **Core Features:** List and describe the system features.
    
5.  **Work Plan:** Define 3 successive phases (sprints) for implementation.
    
6.  **Metrics:** Identify metrics to measure success (e.g., manual process vs. systemic solution).
    

### Submission Instructions

-   **Format:** Collaborate via Google Docs, export as **PDF**.
    
-   **Attribution:** Include names of all contributing team members at the top.
    
-   **Requirement:** Every team member must submit their own copy of the PDF in Teams.
