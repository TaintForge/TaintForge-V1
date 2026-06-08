Summary

A low privileged user can store a malicious full name that later reaches the random_assign automation SQL path. When prioritize_full_name_in_ux is enabled, discourse_assign stores the user's full name in assignment history. The random_assign automation later reads that stored value and interpolates it into a raw PostgreSQL JOIN unnest clause, allowing stacked SQL execution.

Assigning a user to a topic is a normal administrative and moderation workflow in Discourse. An administrator does not need to enter or approve the malicious SQL text during exploitation. They only assign the low privileged user to a topic, and discourse_assign internally copies that user's full name into action_code_who for the assignment action post. Because that full name is later consumed by random_assign, the vulnerability can be triggered through ordinary site operation without the administrator being aware that attacker controlled full name text was stored in the assignment history.

Root Cause

RandomAssignUtils#recently_assigned_users_ids builds SQL by directly interpolating values from PostCustomField records named action_code_who.

Those values are treated as usernames, but under prioritize_full_name_in_ux, assignment history can contain User.name instead. A normal user can edit their own full name, so attacker controlled text is later reused as trusted SQL input.

The vulnerable query shape is:

```ruby
# link: https://github.com/discourse/discourse/blob/main/plugins/discourse-assign/lib/random_assign_utils.rb#L54
.joins("JOIN unnest('{#{usernames.join(",")}}'::text[]) WITH ORDINALITY t(username, ord) USING(username)")
```

Because the stored value is inserted into the PostgreSQL array literal without escaping or binding, the attacker can close the literal and append SQL.

Details

The issue is caused by a stored data flow across two plugins.

1. A normal user controls User.name through the profile full name field.

2. When an authorized user assigns that account to a topic, discourse_assign creates a small action post for the assignment.

3. If prioritize_full_name_in_ux is enabled, discourse_assign stores the assigned user's full name in the small action custom field action_code_who.

4. Later, random_assign reads prior assignment history from action_code_who for the target topic.

5. random_assign assumes those values are usernames and inserts them into a raw PostgreSQL array literal.

The assignment route sends PUT /assign/assign to DiscourseAssign::AssignController#assign:

```ruby
# link: https://github.com/discourse/discourse/blob/main/plugins/discourse-assign/config/routes.rb#L5
put "/assign" => "assign#assign"
```

DiscourseAssign::AssignController#assign resolves the supplied username, loads the target topic or post, and calls Assigner#assign:

```ruby
# link: https://github.com/discourse/discourse/blob/main/plugins/discourse-assign/app/controllers/discourse_assign/assign_controller.rb#L39
def assign
  target_id = params.require(:target_id)
  target_type = params.require(:target_type)
  username = params.permit(:username)["username"]
  group_name = params.permit(:group_name)["group_name"]
  note = params.permit(:note)["note"].presence
  status = params.permit(:status)["status"].presence
  should_notify = params.permit(:should_notify)["should_notify"]
  should_notify = (should_notify.present? ? should_notify.to_s == "true" : true)

  assign_to =
    (
      if username.present?
        User.find_by(username_lower: username.downcase)
      else
        Group.where("LOWER(name) = ?", group_name.downcase).first
      end
    )

  raise Discourse::NotFound unless assign_to
  raise Discourse::NotFound if !Assignment.valid_type?(target_type)
  target = target_type.constantize.where(id: target_id).first
  raise Discourse::NotFound if target.blank? || !guardian.can_see?(target)

  assign =
    Assigner.new(target, current_user).assign(
      assign_to,
      note: note,
      status: status,
      should_notify: should_notify,
    )

  if assign[:success]
    render json: success_json
  else
    render json: translate_failure(assign[:reason], assign_to), status: :bad_request
  end
end
```

The first relevant storage function is Assigner#small_action_username_or_name:

```ruby
# link: https://github.com/discourse/discourse/blob/bfeb7dbd82b3c4e05098682d2914dd01e4896edd/plugins/discourse-assign/lib/assigner.rb#L494
def small_action_username_or_name(assign_to)
  if (assign_to.is_a?(User) && SiteSetting.prioritize_full_name_in_ux) ||
       !assign_to.try(:username)
    custom_fields = { "action_code_who" => assign_to.name || assign_to.username }
  else
    custom_fields = {
      "action_code_who" => assign_to.is_a?(User) ? assign_to.username : assign_to.name,
    }
  end
  custom_fields
end
```

This means that when prioritize_full_name_in_ux is enabled, a user controlled profile value is copied into assignment history. That copy happens at assignment time. Changing the user's full name after an assignment does not update older action_code_who values, which is why the malicious full name must be set before the assignment record is created.

Assigner#add_small_action_post then passes that custom field into topic.add_moderator_post:

```ruby
# link: https://github.com/discourse/discourse/blob/bfeb7dbd82b3c4e05098682d2914dd01e4896edd/plugins/discourse-assign/lib/assigner.rb#L506
def add_small_action_post(action_code, assign_to, text)
  custom_fields = small_action_username_or_name(assign_to)

  if post_target?
    custom_fields.merge!(
      { "action_code_path" => "/p/#{@target.id}", "action_code_post_id" => @target.id },
    )
  end

  topic.add_moderator_post(
    @assigned_by,
    text,
    bump: false,
    auto_track: false,
    post_type: SiteSetting.assigns_public ? Post.types[:small_action] : Post.types[:whisper],
    action_code: action_code,
    custom_fields: custom_fields,
  )
end
```

The random_assign automation script is registered by add_automation_scriptable and calls RandomAssignUtils.automation_script!:

```ruby
# link: https://github.com/discourse/discourse/blob/bfeb7dbd82b3c4e05098682d2914dd01e4896edd/plugins/discourse-assign/plugin.rb#L1024
if defined?(DiscourseAutomation)
  add_automation_scriptable("random_assign") do
    field :assignees_group, component: :group, required: true
    field :assigned_topic, component: :text, required: true
    field :minimum_time_between_assignments, component: :text
    field :max_recently_assigned_days, component: :text
    field :min_recently_assigned_days, component: :text
    field :skip_new_users_for_days, component: :text
    field :in_working_hours, component: :boolean
    field :post_template, component: :post

    version 1

    triggerables %i[point_in_time recurring]

    script do |context, fields, automation|
      RandomAssignUtils.automation_script!(context, fields, automation)
    end
  end
end
```

RandomAssignUtils.automation_script! is the class method entry point used by the automation script:

```ruby
# link: https://github.com/discourse/discourse/blob/bfeb7dbd82b3c4e05098682d2914dd01e4896edd/plugins/discourse-assign/lib/random_assign_utils.rb#L6
def self.automation_script!(...)
  new(...).automation_script!
end
```

RandomAssignUtils#automation_script! is the instance method that runs the assignment flow and reaches recently_assigned_users_ids through assigned_user:

```ruby
# link: https://github.com/discourse/discourse/blob/bfeb7dbd82b3c4e05098682d2914dd01e4896edd/plugins/discourse-assign/lib/random_assign_utils.rb#L31
def automation_script!
  return log_info("Topic(#{topic.id}) has already been assigned recently") if assigned_recently?
  return no_one! unless assigned_user
  assign_user!
end
```

The automation creation and update routes are:

```ruby
# link: https://github.com/discourse/discourse/blob/bfeb7dbd82b3c4e05098682d2914dd01e4896edd/plugins/automation/config/routes.rb#L28
put "/automations/:id" => "admin_automations#update"

# link: https://github.com/discourse/discourse/blob/bfeb7dbd82b3c4e05098682d2914dd01e4896edd/plugins/automation/config/routes.rb#L29
post "/automations" => "admin_automations#create"
```

DiscourseAutomation::AdminAutomationsController#create creates the automation record:

```ruby
# link: https://github.com/discourse/discourse/blob/bfeb7dbd82b3c4e05098682d2914dd01e4896edd/plugins/automation/app/controllers/discourse_automation/admin_automations_controller.rb#L37
def create
  DiscourseAutomation::Create.call(
    params: params.require(:automation).to_unsafe_h,
    guardian:,
  ) do
    on_success { |automation:| render_serialized_automation(automation) }
    on_failed_policy(:can_create_automation) { raise Discourse::InvalidAccess }
    on_failed_contract do |contract|
      render json: failed_json.merge(errors: contract.errors.full_messages),
             status: :bad_request
    end
    on_failure { raise Discourse::InvalidParameters }
  end
end
```

DiscourseAutomation::AdminAutomationsController#update stores the script, trigger, enabled state, and field values used by random_assign:

```ruby
# link: https://github.com/discourse/discourse/blob/bfeb7dbd82b3c4e05098682d2914dd01e4896edd/plugins/automation/app/controllers/discourse_automation/admin_automations_controller.rb#L52
def update
  DiscourseAutomation::Update.call(
    params: params.require(:automation).to_unsafe_h.merge(automation_id: params[:id]),
    guardian:,
  ) do
    on_success { |automation:| render_serialized_automation(automation) }
    on_model_not_found(:automation) { raise Discourse::NotFound }
    on_failed_policy(:can_update_automation) { raise Discourse::InvalidAccess }
    on_failed_contract do |contract|
      render json: failed_json.merge(errors: contract.errors.full_messages),
             status: :bad_request
    end
    on_failure { raise Discourse::InvalidParameters }
  end
end
```

The manual trigger route sends POST /automations/:id/trigger to DiscourseAutomation::AutomationsController#trigger:

```ruby
# link: https://github.com/discourse/discourse/blob/bfeb7dbd82b3c4e05098682d2914dd01e4896edd/plugins/automation/config/routes.rb#L5
post "/automations/:id/trigger" => "automations#trigger"
```

DiscourseAutomation::AutomationsController#trigger enqueues the automation execution:

```ruby
# link: https://github.com/discourse/discourse/blob/bfeb7dbd82b3c4e05098682d2914dd01e4896edd/plugins/automation/app/controllers/discourse_automation/automations_controller.rb#L8
def trigger
  automation = DiscourseAutomation::Automation.find(params[:id])
  automation.trigger_in_background!(
    params.to_unsafe_h.merge(kind: DiscourseAutomation::Triggers::API_CALL),
  )
  render json: success_json
end
```

The second relevant SQL function is RandomAssignUtils#recently_assigned_users_ids:

```ruby
# link: https://github.com/discourse/discourse/blob/bfeb7dbd82b3c4e05098682d2914dd01e4896edd/plugins/discourse-assign/lib/random_assign_utils.rb#L37
def recently_assigned_users_ids(from)
  usernames =
    PostCustomField
      .joins(:post)
      .where(
        name: "action_code_who",
        posts: {
          topic: topic,
          action_code: %w[assigned reassigned assigned_to_post],
        },
      )
      .where("posts.created_at > ?", from)
      .order("posts.created_at DESC")
      .pluck(:value)
      .uniq
  User
    .where(username: usernames)
    .joins(
      # link: https://github.com/discourse/discourse/blob/bfeb7dbd82b3c4e05098682d2914dd01e4896edd/plugins/discourse-assign/lib/random_assign_utils.rb#L54
      "JOIN unnest('{#{usernames.join(",")}}'::text[]) WITH ORDINALITY t(username, ord) USING(username)",
    )
    .limit(100)
    .order("ord")
    .pluck(:id)
end
```

This function fetches the stored action_code_who values from assignment history. The variable is named usernames, but the values can actually be full names controlled by users. The User.where call does not make the raw join safe. The injected value is already inside the joins string, so PostgreSQL parses the attacker controlled text as part of the SQL statement before the later username predicate can limit the result set.

The full exploitation flow is:

1. The low privileged user stores a SQL payload in their full name.

2. An authorized user assigns that account to the target topic.

3. discourse_assign copies the payload into action_code_who on the assignment small action post.

4. A random_assign automation runs for the same topic.

5. random_assign loads action_code_who from the topic assignment history.

6. The payload is interpolated into the raw JOIN unnest SQL fragment.

7. PostgreSQL parses the appended SQL statement.

In the tested environment, the injected statement reached PostgreSQL and attempted COPY TO PROGRAM. PostgreSQL then blocked OS command execution because the Discourse database role did not have pg_execute_server_program.

The observed exception was:

```text
PG::InsufficientPrivilege: ERROR: must be superuser or have privileges of the pg_execute_server_program role to COPY to or from an external program
```

This confirms that the stacked statement reached the PostgreSQL privilege check.

Steps to reproduce

1. Enable the required features.

```ruby
SiteSetting.assign_enabled = true
SiteSetting.discourse_automation_enabled = true
SiteSetting.prioritize_full_name_in_ux = true
```

2. As a low privileged user, set the full name to a payload that escapes the PostgreSQL array literal and appends a second SQL statement.

3. As an authorized user, assign that low privileged user to a topic.

4. Create a random_assign automation.

```text
Script: random_assign
Trigger: recurring
Assignees Group: staff
Assigned Topic ID: target topic id
```

5. Enable the automation and trigger it manually, or wait for a scheduled recurring run.

6. Observe that the injected SQL reaches PostgreSQL. In the tested environment, PostgreSQL rejected COPY TO PROGRAM with an insufficient privilege error.

Impact

This is a stored second order SQL injection reachable through normal assignment and automation workflows when the required plugins and settings are enabled.

An attacker can persist a payload through their profile name and wait for a privileged workflow to store and trigger it. The impact includes arbitrary SQL execution as the Discourse database role. Depending on database permissions, this can allow data extraction, data modification, authentication bypass through database changes, and other database level compromise.

If the Discourse database role has pg_execute_server_program or superuser privileges, the same primitive can escalate to OS command execution through PostgreSQL COPY TO PROGRAM. In the tested environment, that final command execution step was blocked only by PostgreSQL role permissions.

Docker build and installation for local validation

The following setup builds and installs a local Discourse Docker instance suitable for validating this issue. The commands assume the Discourse Docker repository is available at /home/pocas/TaintForge-V1/targets/discourse_docker and the Discourse application checkout is available at /home/pocas/TaintForge-V1/targets/discourse.

Build the Discourse base image from the Dockerfile:

```bash
cd /home/pocas/TaintForge-V1/targets/discourse_docker/image
ruby auto_build.rb base_release_main_amd64
```

The command above builds image/base/Dockerfile with the discourse-release target and produces the local image tag discourse/base:build_release_main_amd64.

Create or update the standalone container config:

```bash
cd /home/pocas/TaintForge-V1/targets/discourse_docker
cp samples/standalone.yml containers/app.yml
```

Set these values in containers/app.yml:

```yaml
templates:
  - "templates/postgres.template.yml"
  - "templates/redis.template.yml"
  - "templates/web.template.yml"
  - "templates/web.ratelimited.template.yml"

expose:
  - "31655:80"

env:
  DISCOURSE_HOSTNAME: "wsl.evm.pics"
  DISCOURSE_PORT: "31655"
  DISCOURSE_DEVELOPER_EMAILS: "pocas@theori.io"
  DISCOURSE_SMTP_ADDRESS: smtp.example.com
  DISCOURSE_SMTP_USER_NAME: user@example.com
  DISCOURSE_SMTP_PASSWORD: "pa$$word"
  DISCOURSE_SKIP_EMAIL_SETUP: "1"
```

Install and start the application container:

```bash
cd /home/pocas/TaintForge-V1/targets/discourse_docker
./launcher rebuild app
```

Enter the running container and create the initial admin and guest accounts for the validation:

```bash
cd /home/pocas/TaintForge-V1/targets/discourse_docker
./launcher enter app
```

Inside the container, run:

```bash
RAILS_ENV=production bin/rails runner 'admin = User.find_by(username: "admin") || User.new(username: "admin", email: "admin@wsl.evm.pics"); admin.admin = true; admin.moderator = true; admin.active = true; admin.approved = true; admin.password = "TK5pYMLOQxZEVh1eAfmj"; admin.save!; guest = User.find_by(username: "guest") || User.new(username: "guest", email: "guest@wsl.evm.pics"); guest.active = true; guest.approved = true; guest.password = "guest-password-2026"; guest.save!; puts "ready"'
```

Enable the required Discourse settings:

```bash
RAILS_ENV=production bin/rails runner 'SiteSetting.assign_enabled = true; SiteSetting.discourse_automation_enabled = true; SiteSetting.prioritize_full_name_in_ux = true; SiteSetting.assign_allowed_on_groups = [Group::AUTO_GROUPS[:staff], Group::AUTO_GROUPS[:trust_level_0]].join("|"); puts "settings ready"'
```

For the maximum impact COPY TO PROGRAM validation, grant the PostgreSQL role needed by PostgreSQL:

```bash
su - postgres -c "psql -d discourse -c 'GRANT pg_execute_server_program TO discourse;'"
```

Verify the database privilege:

```bash
su - postgres -c "psql -At -d discourse -c \"SELECT pg_has_role('discourse','pg_execute_server_program','member');\""
```

The expected output is:

```text
t
```

If the application keeps using an old database connection, restart the web process:

```bash
sv restart unicorn
```

After validation, revoke the lab privilege:

```bash
su - postgres -c "psql -d discourse -c 'REVOKE pg_execute_server_program FROM discourse;'"
```
